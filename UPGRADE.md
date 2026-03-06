# Go Version Upgrade Guide

This document outlines the process for upgrading the Go version used in this project. To ensure consistency, security, and access to the latest features, all Go modules and associated configurations must be updated.

## Step 1: Automated Go Module Update

A script is provided to update the `go` directive and dependencies in all `go.mod` files across the project.

**To run the script:**

Execute the following command from the project root:
```sh
./scripts/update_go
```

This will modify the following files:
*   `config/go.mod`
*   `pcap-cli/go.mod`
*   `pcap-fsnotify/go.mod`
*   `tcpdumpw/go.mod`

## Step 2: Manual File Updates

After running the script, you must manually update the Go version and related dependencies in the files listed below.

### Dockerfiles

Update the `GO_VERSION` or base image tag in the following Dockerfiles:

*   `base-image/golang.Dockerfile`
*   `base-image/sidecar.Dockerfile`
*   `config/Dockerfile`
*   `gcsfuse/Dockerfile`
*   `pcap-cli/Dockerfile`
*   `pcap-fsnotify/Dockerfile`
*   `supervisord/Dockerfile`
*   `tcpdumpw/Dockerfile`

### Environment Files

Update the `GO_VERSION` in these environment configuration files:

*   `env/cloud_run_gen1.env`
*   `env/cloud_run_gen2.env`
*   `tcpdumpw/.env`
