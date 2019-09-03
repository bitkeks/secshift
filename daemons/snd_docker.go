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

package daemons

import (
	"context"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
)

// Find Docker containers which match the type Pod and name
func (s *snd) findPodContainer(podName string) types.Container {
	args := filters.NewArgs(
		filters.Arg("label", "io.kubernetes.container.name=POD"),
		filters.Arg("label", "io.kubernetes.pod.name="+podName),
	)

	containers, err := s.dclient.ContainerList(context.Background(), types.ContainerListOptions{Filters: args})
	if err != nil {
		s.logger.Fatal(err)
	}

	if len(containers) > 1 {
		s.logger.Fatal("More than one Container was matched!")
	}

	if len(containers) == 0 {
		s.logger.Info("No Container was found with Pod name " + podName)
	}

	return containers[0]
}

func (s *snd) getPodPid(container types.Container) int {
	inspected, err := s.dclient.ContainerInspect(context.Background(), container.ID)
	if err != nil {
		s.logger.Fatal(err)
	}

	//~ fmt.Printf("%s %s\n", container.ID[:10], container.Image)
	//~ fmt.Printf("%+v\n", container)
	return inspected.State.Pid
}
