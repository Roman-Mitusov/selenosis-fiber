package tools

import (
	"fmt"
	"github.com/gofiber/fiber/v2"
	"net"
	"time"
)

func TimeElapsed(t time.Time) string {
	return fmt.Sprintf("%.2fs", time.Since(t).Seconds())
}

//func JSONError(w http.ResponseWriter, message string, statusCode int) {
//	w.Header().Set("Content-Type", "application/json")
//	w.WriteHeader(statusCode)
//	json.NewEncoder(w).Encode(
//		map[string]interface{}{
//			"value": map[string]string{
//				"message": message,
//			},
//			"code": statusCode,
//		},
//	)
//}

func JSONError(errorDesc, message string, statusCode int, ctx *fiber.Ctx) error {
	return ctx.Status(statusCode).JSON(fiber.Map{
		"value": map[string]string{
			"error":   errorDesc,
			"message": message,
		},
	})
}

func BuildHostPort(session, service, port string) string {
	return net.JoinHostPort(fmt.Sprintf("%s.%s", session, service), port)
}
