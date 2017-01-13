PROJECT_NAME := aporetolaunch


build: systemdutil.go
	go build -o $(PROJECT_NAME)

package:
	@mkdir -p $(GOPATH)/bin
	mv  $(PROJECT_NAME) $(GOPATH)/bin/$(PROJECT_NAME)
