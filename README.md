# Markado Backend

This repository contains the backend services for the Markado project. The backend is built using Go and provides various APIs for managing and interacting with the Markado platform.

## Table of Contents

- [Markado Backend](#markado-backend)
  - [Table of Contents](#table-of-contents)
  - [Getting Started](#getting-started)
    - [Prerequisites](#prerequisites)
    - [Installation](#installation)
    - [Running the Application](#running-the-application)
    - [Running Tests](#running-tests)

## Getting Started

These instructions will help you set up and run the backend services on your local machine for development and testing purposes.

### Prerequisites

- Go 1.16 or higher
- Docker (for running the database and other services)
- Make (optional, for using the Makefile)

### Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/yourusername/markado-backend.git
    cd markado-backend
    ```

2. Install dependencies:

    ```sh
    go mod tidy
    ```

### Running the Application

1. Start the required services using Docker:

    ```sh
    docker-compose up -d
    ```

2. Run the application:

    ```sh
    go run main.go
    ```

### Running Tests

To run the tests, use the following command:

```sh
go test ./...