package main

import (
    "encoding/json"
    "errors"
    "fmt"
    "net/http"
    "os"

    "github.com/github/github-mcp-server/internal/ghmcp"
    "github.com/github/github-mcp-server/pkg/github"
    "github.com/gorilla/mux"
    "github.com/spf13/cobra"
    "github.com/spf13/viper"
)

// MCP Protocol definitions
type MCPContext struct {
    Version     string
    Environment string
    Toolsets    []string
    Config      *MCPConfig
}

type MCPConfig struct {
    IsReadOnly    bool
    IsDynamic     bool
    EnableLogging bool
    Host          string
}

type MCPResponse struct {
    Success bool        `json:"success"`
    Data    interface{} `json:"data"`
    Error   string      `json:"error,omitempty"`
    Status  int         `json:"status"`
}

// API route structures
type HealthCheck struct {
    Status    string `json:"status"`
    Version   string `json:"version"`
    Timestamp string `json:"timestamp"`
}

type ToolsetResponse struct {
    Name        string   `json:"name"`
    Tools       []string `json:"tools"`
    IsEnabled   bool     `json:"isEnabled"`
    Description string   `json:"description"`
}

var (
    // Global variables
    version    = "version"
    commit     = "commit"
    date       = "date"
    mcpContext *MCPContext
    router     *mux.Router

    // Commands
    rootCmd = &cobra.Command{
        Use:     "server",
        Short:   "GitHub MCP Server",
        Long:    `A GitHub MCP server that handles various tools and resources.`,
        Version: fmt.Sprintf("Version: %s\nCommit: %s\nBuild Date: %s", version, commit, date),
        PersistentPreRun: func(cmd *cobra.Command, args []string) {
            mcpContext = &MCPContext{
                Version:     version,
                Environment: os.Getenv("GITHUB_ENVIRONMENT"),
                Config:      &MCPConfig{},
            }
            setupRouter()
        },
    }

    // API Server command
    apiCmd = &cobra.Command{
        Use:   "api",
        Short: "Start API server",
        Long:  `Start the HTTP API server with MCP endpoints`,
        RunE: func(_ *cobra.Command, _ []string) error {
            port := viper.GetString("port")
            if port == "" {
                port = "8080"
            }
            
            fmt.Printf("Starting API server on port %s...\n", port)
            return http.ListenAndServe(":"+port, router)
        },
    }

    stdioCmd = &cobra.Command{
        Use:   "stdio",
        Short: "Start stdio server",
        Long:  `Start a server that communicates via standard input/output streams using JSON-RPC messages.`,
        RunE:  handleStdioServer,
    }
)

// Router setup
func setupRouter() {
    router = mux.NewRouter()
    
    // API Routes
    api := router.PathPrefix("/api/v1").Subrouter()
    
    // Health check endpoint
    api.HandleFunc("/health", healthCheckHandler).Methods("GET")
    
    // Toolsets endpoints
    api.HandleFunc("/toolsets", listToolsetsHandler).Methods("GET")
    api.HandleFunc("/toolsets/{name}", getToolsetHandler).Methods("GET")
    
    // MCP Status endpoint
    api.HandleFunc("/status", mcpStatusHandler).Methods("GET")
    
    // Middleware
    router.Use(mcpMiddleware)
}

// Middleware
func mcpMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        w.Header().Set("X-MCP-Version", mcpContext.Version)
        next.ServeHTTP(w, r)
    })
}

// Handlers
func healthCheckHandler(w http.ResponseWriter, r *http.Request) {
    response := MCPResponse{
        Success: true,
        Data: HealthCheck{
            Status:    "healthy",
            Version:   version,
            Timestamp: date,
        },
        Status: http.StatusOK,
    }
    json.NewEncoder(w).Encode(response)
}

func listToolsetsHandler(w http.ResponseWriter, r *http.Request) {
    toolsets := []ToolsetResponse{
        {
            Name:        "default",
            Tools:       mcpContext.Toolsets,
            IsEnabled:   true,
            Description: "Default toolset",
        },
    }

    response := MCPResponse{
        Success: true,
        Data:    toolsets,
        Status:  http.StatusOK,
    }
    json.NewEncoder(w).Encode(response)
}

func getToolsetHandler(w http.ResponseWriter, r *http.Request) {
    vars := mux.Vars(r)
    name := vars["name"]

    toolset := ToolsetResponse{
        Name:        name,
        Tools:       mcpContext.Toolsets,
        IsEnabled:   true,
        Description: fmt.Sprintf("Toolset: %s", name),
    }

    response := MCPResponse{
        Success: true,
        Data:    toolset,
        Status:  http.StatusOK,
    }
    json.NewEncoder(w).Encode(response)
}

func mcpStatusHandler(w http.ResponseWriter, r *http.Request) {
    response := MCPResponse{
        Success: true,
        Data:    mcpContext,
        Status:  http.StatusOK,
    }
    json.NewEncoder(w).Encode(response)
}

// Stdio server handler
func handleStdioServer(_ *cobra.Command, _ []string) error {
    token := viper.GetString("personal_access_token")
    if token == "" {
        return createMCPError("GITHUB_PERSONAL_ACCESS_TOKEN not set")
    }

    var enabledToolsets []string
    if err := viper.UnmarshalKey("toolsets", &enabledToolsets); err != nil {
        return createMCPError(fmt.Sprintf("failed to unmarshal toolsets: %v", err))
    }

    mcpContext.Toolsets = enabledToolsets
    mcpContext.Config = &MCPConfig{
        IsReadOnly:    viper.GetBool("read-only"),
        IsDynamic:     viper.GetBool("dynamic_toolsets"),
        EnableLogging: viper.GetBool("enable-command-logging"),
        Host:          viper.GetString("host"),
    }

    stdioServerConfig := ghmcp.StdioServerConfig{
        Version:              version,
        Host:                 mcpContext.Config.Host,
        Token:                token,
        EnabledToolsets:      mcpContext.Toolsets,
        DynamicToolsets:      mcpContext.Config.IsDynamic,
        ReadOnly:             mcpContext.Config.IsReadOnly,
        ExportTranslations:   viper.GetBool("export-translations"),
        EnableCommandLogging: mcpContext.Config.EnableLogging,
        LogFilePath:          viper.GetString("log-file"),
    }

    return handleMCPResponse(ghmcp.RunStdioServer(stdioServerConfig))
}

// Helper functions
func createMCPError(message string) error {
    return errors.New(message)
}

func handleMCPResponse(err error) error {
    if err != nil {
        return err
    }
    return nil
}

func init() {
    cobra.OnInitialize(initConfig)
    rootCmd.SetVersionTemplate("{{.Short}}\n{{.Version}}\n")

    // Add global flags
    rootCmd.Persist
