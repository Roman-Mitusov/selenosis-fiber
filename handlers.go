package selenosis_fiber

import (
	"context"
	"fmt"
	httpreverseproxy "github.com/Roman-Mitusov/middleware/proxy/http"
	ws "github.com/Roman-Mitusov/middleware/websocket"
	"github.com/Roman-Mitusov/selenosis-fiber/browser"
	"github.com/Roman-Mitusov/selenosis-fiber/selenium"
	"github.com/Roman-Mitusov/selenosis-fiber/tools"
	"github.com/fasthttp/websocket"
	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/imdario/mergo"
	"github.com/sirupsen/logrus"
	"github.com/valyala/fasthttp"
	"io"
	"regexp"
	"strings"
	"sync"
	"time"
)

var httpClient = fasthttp.Client{
	NoDefaultUserAgentHeader: true,
	DisablePathNormalizing:   true,
}

var wg = sync.WaitGroup{}

//CheckLimit ...
func (app *App) CheckLimit(next fiber.Handler) fiber.Handler {
	return func(ctx *fiber.Ctx) error {

		total := app.stats.Len()

		if total >= app.sessionLimit {
			app.logger.Warnf("active session limit reached: total %d, limit %d", total, app.sessionLimit)
			return tools.JSONError("Unable to create new session because session limit is reached", "Session limit reached", fiber.StatusInternalServerError, ctx)
		}

		return next(ctx)
	}
}

//HandleSession ...
//Handle create selenium session POST request
func (app *App) HandleSession(ctx *fiber.Ctx) error {
	req := ctx.Request()
	resp := ctx.Response()
	start := time.Now()
	var err error
	app.logger.WithField("time_elapsed", tools.TimeElapsed(start)).Info("Starting session ...")

	type request struct {
		DesiredCapabilities selenium.Capabilities `json:"desiredCapabilities"`
		Capabilities        struct {
			AlwaysMatch selenium.Capabilities    `json:"alwaysMatch"`
			FirstMatch  []*selenium.Capabilities `json:"firstMatch"`
		} `json:"capabilities"`
	}

	caps := request{}
	err = ctx.BodyParser(&caps)
	if err != nil {
		app.logger.WithField("time_elapsed", tools.TimeElapsed(start)).Errorf("failed to parse request: %v", err)
		_ = tools.JSONError("Unable to parse request body. Reason: failed to parse request", err.Error(), fiber.StatusBadRequest, ctx)
		return err
	}

	caps.DesiredCapabilities.ValidateCapabilities()
	caps.Capabilities.AlwaysMatch.ValidateCapabilities()

	if caps.DesiredCapabilities.BrowserName != "" && caps.Capabilities.AlwaysMatch.BrowserName != "" {
		caps.DesiredCapabilities = caps.Capabilities.AlwaysMatch
	}

	firstMatchCaps := caps.Capabilities.FirstMatch
	if len(firstMatchCaps) == 0 {
		firstMatchCaps = append(firstMatchCaps, &selenium.Capabilities{})
	}

	var browserSpec *browser.SpecForBrowser
	var capabilities selenium.Capabilities

	var browserFindError error
	for _, first := range firstMatchCaps {
		capabilities = caps.DesiredCapabilities
		_ = mergo.Merge(&capabilities, first)
		capabilities.ValidateCapabilities()

		browserSpec, browserFindError = app.browsers.Find(capabilities.BrowserName, capabilities.BrowserVersion)
		if browserFindError == nil {
			break
		}
	}

	if browserFindError != nil {
		app.logger.WithField("time_elapsed", tools.TimeElapsed(start)).Errorf("requested browser not found: %v", err)
		_ = tools.JSONError("Unable to find requested browser", err.Error(), fiber.StatusBadRequest, ctx)
		return browserFindError
	}

	image := parseImage(browserSpec.Image)
	template := &browser.FinalBrowserPodSpec{
		SessionID:             fmt.Sprintf("%s-%s", image, uuid.New()),
		RequestedCapabilities: capabilities,
		Template:              browserSpec,
	}

	app.logger.WithField("time_elapsed", tools.TimeElapsed(start)).Infof("Starting browser from image: %s", template.Template.Image)

	browserPod, err := app.client.Create(template)
	if err != nil {
		app.logger.WithField("time_elapsed", tools.TimeElapsed(start)).Errorf("Failed to start browser pod: %v", err)
		_ = tools.JSONError("Unable to start browser pod", err.Error(), fiber.StatusBadRequest, ctx)
		return err
	}

	cancel := func() {
		browserPod.CancelFunc()
	}

	browserPod.URL.Path = ctx.Path()

	req.SetRequestURI(browserPod.URL.String())
	httpClient.RetryIf = func(r *fasthttp.Request) bool {
		return r.Header.IsPost()
	}
	httpClient.MaxIdemponentCallAttempts = app.sessionRetryCount
	httpClient.ReadTimeout = app.browserWaitTimeout

	if err = httpClient.Do(req, resp); err != nil {
		app.logger.WithField("time_elapsed", tools.TimeElapsed(start)).Errorf("Failed to start selenium session: %v", err)
		_ = tools.JSONError(fmt.Sprintf("Unable to start selenium session. URL=%s, Request body=%v", browserPod.URL.String(), caps), fmt.Sprintf("Failed to start selenium session: URL=%s, Request Body=%v", browserPod.URL.Scheme, caps), fiber.StatusNotFound, ctx)
		cancel()
		return err
	}

	return nil

}

//HandleProxy ...
func (app *App) HandleProxy(ctx *fiber.Ctx) error {
	sessionID := ctx.Params("sessionId")
	if sessionID == "" {
		app.logger.Error("Session id not found")
		_ = tools.JSONError("Unable to find sessionID. It is empty.", "Session id not found", fiber.StatusNotFound, ctx)
		return fmt.Errorf("session id is not found")
	}

	host := tools.BuildHostPort(sessionID, app.serviceName, app.sidecarPort)
	logger := app.logger.WithFields(logrus.Fields{
		"session_id": sessionID,
	})

	return (&httpreverseproxy.ReverseProxy{
		PrepareRequest: func(c *fiber.Ctx) error {
			c.Request().URI().SetScheme("http")
			c.Request().URI().SetHost(host)
			//logger.Infof("Proxying session ...")
			return nil
		},
		HandleError: func(c *fiber.Ctx) error {
			logger.Errorf("Error proxying the session")
			return c.SendStatus(fiber.StatusBadGateway)
		},
	}).Proxy(ctx)

}

//HandleHubStatus ...
//Handle Selenosis status endpoint
func (app *App) HandleHubStatus(ctx *fiber.Ctx) error {

	active, pending := getSessionStats(app.stats.List())
	total := len(active) + len(pending)

	app.logger.WithField("active_sessions", total).Infof("Selenosis status")

	return ctx.JSON(fiber.Map{
		"value": map[string]interface{}{
			"message": "selenosis up and running",
			"ready":   total,
		},
	})

}

//HandleReverseProxy ...
func (app *App) HandleReverseProxy(ctx *fiber.Ctx) error {
	sessionID := ctx.Params("sessionId")

	if sessionID == "" {
		app.logger.Error("Session id not found")
		_ = tools.JSONError("Unable to find sessionID. It is empty.", "Session id not found", fiber.StatusNotFound, ctx)
		return fmt.Errorf("session id is not found")
	}

	fragments := strings.Split(ctx.Path(), "/")
	logger := app.logger.WithFields(logrus.Fields{
		"session_id": sessionID,
	})

	return (&httpreverseproxy.ReverseProxy{
		PrepareRequest: func(c *fiber.Ctx) error {
			c.Request().URI().SetScheme("http")
			c.Request().URI().SetHost(tools.BuildHostPort(sessionID, app.serviceName, app.sidecarPort))
			//logger.Infof("Proxying session %s", fragments[1])
			return nil
		},
		HandleError: func(c *fiber.Ctx) error {
			logger.Errorf("Proxying error %s", fragments[1])
			return c.SendStatus(fiber.StatusBadGateway)
		},
	}).Proxy(ctx)

}

//ProxyVNC ...
//Proxy vnc traffic from browser pod to selenoid_ui
//func (app *App) ProxyVNC(ctx *fiber.Ctx) error {
//	sessionID := ctx.Params("sessionId")
//
//	if sessionID == "" {
//		app.logger.Error("Session id not found")
//		return fmt.Errorf("provided in request session id is not found")
//	}
//
//	return (&tcptowsproxy.TcpToWSProxy{
//		PrepareRequest: func(c *fiber.Ctx) error {
//			host := tools.BuildHostPort(sessionID, app.serviceName, "5900")
//			c.Request().SetHost(host)
//			//if !isHostAlive(host, app) {
//			//	app.logger.Errorf("Error proxying vnc trafic for sessionID=%s", sessionID)
//			//	return fmt.Errorf("cannot reach container host on port 5900")
//			//}
//			return nil
//		},
//	}).ProxyTcpToWS(ctx)
//}
func (app *App) ProxyVNC() fiber.Handler {
	return ws.HandleWebSocket(func(clientConn *ws.Conn) {

		sessionID := clientConn.Params("sessionId")

		if sessionID == "" {
			app.logger.Error("Session id not found")
			return
		}

		host := tools.BuildHostPort(sessionID, app.serviceName, "5900")
		app.logger.Infof("Sending tcp request to vnc host: %s", host)

		vncConn, err := fasthttp.Dial(host)
		if err != nil {
			app.logger.Errorf("Unable to establish tcp connection with vnc host=%s with err=%v", host, err)
			return
		}
		defer vncConn.Close()

		//app.logger.Info("Obtain WebSocket writer from client connection ...")
		//writer, err := clientConn.Conn.NextWriter(websocket.BinaryMessage)
		//if err != nil {
		//	app.logger.Errorf("Unable to obtaim message writer from WebSocket client connection. Err=%v", err)
		//	return
		//}

		//app.logger.Info("Obtain WebSocket reader from client connection")
		//msgType, reader, err := clientConn.NextReader()
		//if err != nil {
		//	app.logger.Errorf("Unable to obtain message reader from WebSocket client connection. Err=%v", err)
		//	return
		//}
		//if msgType != websocket.BinaryMessage {
		//	app.logger.Errorf("The returned from WebSocket client connection message reader is not of Binnary type")
		//	return
		//}

		//go func(writer io.WriteCloser, vncConn net.Conn) {
		//if _, err := io.Copy(writer, vncConn); err != nil {
		//	app.logger.Errorf("Unable to copy from vnc tcp connection to websocket writer. Err=%v", err)
		//	return
		//}
		//app.logger.Warn("Vnc connection closed")
		//}
		wg.Add(2)
		go func() {
			defer wg.Done()
			if _, err := writeStreamToWsConn(clientConn, vncConn, nil, app.logger); err != nil {
				app.logger.Errorf("Unable to copy stream from tcp connection established to host=%s to client WebSocket connection. Err=%v", host, err)
				return
			}
		}()

		go func() {
			defer wg.Done()
			for {
				_, resp, err := clientConn.ReadMessage()
				if err != nil {
					app.logger.Warn("End of vnc stream ")
					return
				} else {
					_, _ = vncConn.Write(resp)
				}
			}
		}()
		wg.Wait()

		//go func(vncConn net.Conn, reader io.Reader) {
		//	io.Copy(vncConn, reader)
		//}(vncConn, reader)

		app.logger.Warn("Vnc client disconnected")

	})
}

//ProxyLogs ...
//Proxy logs from browser pod to selenoid_ui
//func (app *App) ProxyLogs(ctx *fiber.Ctx) error {
//	sessionID := ctx.Params("sessionId")
//
//	if sessionID == "" {
//		app.logger.Error("Session id not found")
//		return fmt.Errorf("provided in request session id is not found")
//	}
//
//	logger := app.logger.WithFields(logrus.Fields{
//		"url_path":  ctx.Path(),
//		"sessionID": sessionID,
//		"full_url":  ctx.Request().URI(),
//	})
//
//	return (&streamproxy.WSStreamReverseProxy{
//		PrepareStream: func() (io.ReadCloser, error) {
//			//sidecarHost := tools.BuildHostPort(sessionID, app.serviceName, app.sidecarPort)
//			//if !isHostAlive(sidecarHost, app) {
//			//	app.logger.Errorf("Error proxying vnc trafic for sessionID=%s", sessionID)
//			//	return nil, fmt.Errorf("cannot reach container host on port=%s", app.sidecarPort)
//			//}
//			//resp,_ := app.client.Logs(context.Background(), sessionID)
//			//ctx.SendStream(resp)
//			logger.Info("========Getting logs==============")
//			return app.client.Logs(context.Background(), sessionID)
//		},
//	}).ProxyStream(ctx)
//
//}
func (app *App) ProxyLogs() fiber.Handler {
	return ws.HandleWebSocket(func(clientConn *ws.Conn) {

		sessionID := clientConn.Params("sessionId")

		if sessionID == "" {
			app.logger.Error("Session id not found")
			return
		}

		resp, err := app.client.Logs(context.Background(), sessionID)
		if err != nil {
			app.logger.Errorf("Unable to get logs from pod with name=%s. Err=%v", sessionID, err)
			return
		}

		//app.logger.Info("Obtain WebSocket writer from client connection ...")
		//writer, err := clientConn.Conn.NextWriter(websocket.BinaryMessage)
		//if err != nil {
		//	app.logger.Errorf("Unable to obtaim message writer from WebSocket client connection. Err=%v", err)
		//	return
		//}

		//go func(writer io.WriteCloser, resp io.ReadCloser) {
		//_, _ = io.Copy(writer, resp)
		//}(writer, resp)
		go func() {
			if _, err := writeStreamToWsConn(clientConn, resp, nil, app.logger); err != nil {
				app.logger.Errorf("Unable to copy stream from kubernetes pod log host=%s to client WebSocket connection. Err=%v", sessionID, err)
				return
			}
		}()

	})
}

//HandleStatus ...
func (app *App) HandleStatus(ctx *fiber.Ctx) error {

	type Status struct {
		Total    int                         `json:"total"`
		Active   int                         `json:"active"`
		Pending  int                         `json:"pending"`
		Browsers map[string][]string         `json:"config,omitempty"`
		Sessions []browser.RunningBrowserPod `json:"sessions,omitempty"`
	}

	type Response struct {
		Status    int    `json:"status"`
		Version   string `json:"version"`
		Error     string `json:"err,omitempty"`
		Selenosis Status `json:"selenosis,omitempty"`
	}

	active, pending := getSessionStats(app.stats.List())

	return ctx.JSON(
		Response{
			Status:  fiber.StatusOK,
			Version: app.buildVersion,
			Selenosis: Status{
				Total:    app.sessionLimit,
				Active:   len(active),
				Pending:  len(pending),
				Browsers: app.browsers.GetBrowserVersions(),
				Sessions: active,
			},
		},
	)

}

func isHostAlive(host string, app *App) bool {
	conn, err := fasthttp.DialTimeout(host, 2*time.Second)
	if err != nil {
		app.logger.Errorf("Host is unreachable. Host=%s", host)
		return false
	}
	_ = conn.Close()
	return true
}

func parseImage(image string) (container string) {
	pref, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return "selenoid-browser"
	}
	return pref.ReplaceAllString(image, "-")
}

func getSessionStats(sessions []browser.RunningBrowserPod) (active []browser.RunningBrowserPod, pending []browser.RunningBrowserPod) {
	active = make([]browser.RunningBrowserPod, 0)
	pending = make([]browser.RunningBrowserPod, 0)

	for _, s := range sessions {
		switch s.Status {
		case browser.Running:
			active = append(active, s)
		case browser.Pending:
			pending = append(pending, s)
		}
	}
	return
}

func writeStreamToWsConn(dst *ws.Conn, src io.ReadCloser, buf []byte, logger *logrus.Logger) (written int64, err error) {
	if buf == nil {
		size := 32 * 1024
		buf = make([]byte, size)
	}
	writer, wrErr := dst.NextWriter(websocket.BinaryMessage)
	if wrErr != nil {
		logger.Errorf("Unale to obtain writer from WebSocket connection. Err=%v", wrErr)
		err = wrErr
		return 0, wrErr
	}
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := writer.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				_ = writer.Close()
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				_ = writer.Close()
				break
			}
			err = writer.Close()
		}
		if er != nil {
			if er != io.EOF {
				err = er
			}
			break
		}
	}
	return written, err

}
