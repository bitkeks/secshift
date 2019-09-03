// SecShift - traffic security for OpenShift
// Copyright (C) 2019 Dominik Pataky <mail@dpataky.eu>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package secshift

import (
	"crypto/tls"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/sirupsen/logrus"

	"secshift/daemons"
)

// Entry function for main.go which imports the secshift package
func Start() {
	logger := logrus.New()

	// Check whether it runs on Master or not
	if _, err := os.Stat("/etc/origin/master"); !os.IsNotExist(err) {
		logger.Fatal("Running on Master, but SecShift is intended for Nodes only!")
	}

	var localInterface = flag.String("interface", "wg0", "The interface to be used for remote peerings")
	var tokenF = flag.String("token", "", "ServiceAccount token for OpenShift API access")
	flag.Parse()

	// Disable TLS certificate checking
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	// Configure the API token
	// Examine if token was a file to read
	var token string
	if len(*tokenF) > 100 {
		// Pretty sure it's a string token
		token = *tokenF
	} else if _, err := os.Stat(*tokenF); os.IsNotExist(err) {
		// Token was passed as string on CLI
		token = *tokenF
	} else {
		// Token is a file, reading it
		buf, err := ioutil.ReadFile(*tokenF)
		if err != nil {
			logger.Fatal(err)
		}
		token = strings.TrimSpace(string(buf))
	}

	if t := os.Getenv("TOKEN"); t == "" {
		logger.Fatal("Token must be set!")
	} else {
		token = t
	}

	logger.Debugf("Running SND on interface %s", *localInterface)
	snd := daemons.CreateSND(token, *localInterface)
	snd.Start()
}
