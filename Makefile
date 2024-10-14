# Copyright © 2020 Jaume Martin
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 	http://www.apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Release specific
VERSION=v0.1.1-dev

# Build parameters
BUILDDIR=build/
BINARYNAME=yamat
BUILDTIME=`date +%FT%T%z`
BUILDHASH=`git log -1 --pretty=format:"%h"`
PLATFORMS="windows/amd64" \
		  "windows/386" \
		  "darwin/amd64" \
		  "linux/amd64" \
		  "linux/386"
LDFLAGS=-s \
	-w \
	-X \"main.Version=${VERSION}\" \
	-X \"main.BuildHash=${BUILDHASH}\" \
	-X \"main.BuildTime=${BUILDTIME}\"

# Docker specific
DOCKER_TAG=--tag  $(BINARYNAME):$(VERSION) \
		   --tag $(BINARYNAME):latest
DOCKER_ARGS=--build-arg GOOS=linux \
			--build-arg GOARCH=amd64 \
			--build-arg VERSION=$(VERSION) \
			--build-arg BUILDHASH=$(BUILDHASH) \
			--build-arg BUILDTIME=$(BUILDTIME)

ARGS?=

SRC=$(wildcard *.go)

all: run build

build: $(SRC)
	go mod tidy ; \
	go mod download ; \
	for platform in $(PLATFORMS) ; \
	do \
		GOOS=$$(printf "$$platform" | cut -d'/' -f1) ; \
		GOARCH=$$(printf "$$platform" | cut -d'/' -f2) ; \
		output_name="$(BINARYNAME)-$$GOOS-$$GOARCH" ; \
		if [ $$GOOS = "windows" ] ; \
		then \
        	output_name="$$output_name".exe ; \
    	fi ; \
		echo "Building $$GOOS-$$GOARCH ..." ; \
		GOOS=$$GOOS GOARCH=$$GOARCH go build -o $(BUILDDIR)$$output_name -ldflags "$(LDFLAGS)" $(SRC) ; \
		if [ $$? -ne 0 ] ; \
		then \
			echo 'An error has occurred! Aborting the script execution...' ; \
			exit 1 ; \
		fi ; \
		echo "\n" ; \
	done;

run: $(SRC)
	go run *.go $(ARGS)

docker:
	docker build $(DOCKER_ARGS) $(DOCKER_TAG) --file Dockerfile .

clean: 
	rm -rf $(BUILDDIR)

.PHONY: all run build clean
