package main

import (

	"context"  //passed to the server's graceful shutdown
	"errors"  //checking for http.ErrServerClosed
	"fmt"  //printing startup messages
	"net"  //building the listen address string
	"net/http"  //the HTTP server itself
	"os"  //signal handling, stderr
	"os/exec"  //launching the browser for --open
	"os/signal"  //catching Ctrl+C for graceful shutdown
	"runtime"  //choosing the right command to open a browser per OS
	"time"  //server timeouts

	"github.com/spf13/cobra"

	"github.com/southwickio/deadkey/internal/config"
	"github.com/southwickio/deadkey/internal/dashboard"
	"github.com/southwickio/deadkey/internal/storage"

)

var (

	servePort int
	serveHost string
	serveOpen bool

)

var serveCmd = &cobra.Command{

	Use:   "serve",
	Short: "Run the local dashboard",
	Long: `Serve starts a local web dashboard reading from your local scan
results. No cloud component required`,
	RunE: runServe,

}

func init() {

	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().IntVar(&servePort, "port", 8420, "port to listen on")
	serveCmd.Flags().StringVar(&serveHost, "host", "127.0.0.1", "address to bind to")
	serveCmd.Flags().BoolVar(&serveOpen, "open", false, "open the dashboard in your default browser")

}

func runServe(cmd *cobra.Command, args []string) error {

	cfg, err := config.Load(resolvedConfigDir)
	if err != nil {

		return err

	}

	db, err := storage.Open(resolvedConfigDir)
	if err != nil {

		return err

	}
	defer db.Close()

	if warning := dashboard.HostWarning(serveHost); warning != "" && !quiet {

		fmt.Fprintln(os.Stderr, "Warning:", warning)

	}

	handler, err := dashboard.NewHandler(db, cfg, serveHost)
	if err != nil {

		return err

	}

	addr := net.JoinHostPort(serveHost, fmt.Sprintf("%d", servePort))

	srv := &http.Server{

		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,

	}

	//Listen explicitly, rather than letting ListenAndServe do it internally,
	//so a "port already in use" failure can be reported clearly before the
	//server ever starts, instead of surfacing as a raw net.OpError from
	//inside ListenAndServe
	listener, err := net.Listen("tcp", addr)
	if err != nil {

		return fmt.Errorf("deadkey: could not start the dashboard on %s (%w) - try a different --port, or check whether `deadkey serve` is already running", addr, err)

	}

	//Graceful shutdown: catch Ctrl+C/SIGTERM and give in-flight requests a
	//moment to finish and the database connection a clean close, rather than
	//the process being killed mid-request
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go func() {

		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)

	}()

	url := fmt.Sprintf("http://%s", addr)
	if !quiet {

		fmt.Printf("deadkey dashboard running at %s (Ctrl+C to stop)\n", url)

	}

	if serveOpen {

		openBrowser(url)

	}

	if err := srv.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {

		return err

	}

	return nil

}

//openBrowser launches the OS's default browser at url. Best-effort: a
//failure here (no display available, unusual environment, unrecognized OS)
//is printed as a note, never fatal - --open is a convenience, not something
//`serve` should refuse to run without
func openBrowser(url string) {

	var cmd *exec.Cmd

	switch runtime.GOOS {

	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)

	}

	if err := cmd.Start(); err != nil {

		fmt.Fprintf(os.Stderr, "deadkey: could not open a browser automatically (%v) - open %s manually\n", err, url)

	}

}
