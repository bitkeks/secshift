module secshift

go 1.12

replace (
	github.com/Sirupsen/logrus v1.0.5 => github.com/sirupsen/logrus v1.0.5
	github.com/Sirupsen/logrus v1.3.0 => github.com/Sirupsen/logrus v1.0.6
	github.com/Sirupsen/logrus v1.4.0 => github.com/sirupsen/logrus v1.0.6
)

require (
	github.com/Azure/go-ansiterm v0.0.0-20170929234023-d6e3b3328b78 // indirect
	github.com/Microsoft/go-winio v0.4.12 // indirect
	github.com/coreos/go-iptables v0.4.1
	github.com/docker/distribution v2.7.1+incompatible // indirect
	github.com/docker/docker v0.7.3-0.20190603204608-3d21b86e0a44
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/docker/libcontainer v2.2.1+incompatible
	github.com/google/gopacket v1.1.17
	github.com/gorilla/mux v1.7.2 // indirect
	github.com/morikuni/aec v0.0.0-20170113033406-39771216ff4c // indirect
	github.com/opencontainers/go-digest v1.0.0-rc1 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/openshift/api v3.9.0+incompatible
	github.com/pkg/errors v0.8.1 // indirect
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.3.0 // indirect
	github.com/vishvananda/netlink v1.0.1-0.20190604022042-c8c507c80ea2
	github.com/vishvananda/netns v0.0.0-20180720170159-13995c7128cc
	golang.org/x/time v0.0.0-20190308202827-9d24e82272b4 // indirect
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20190603170153-16c2a93f1c5e
	google.golang.org/grpc v1.21.0 // indirect
	gotest.tools v2.2.0+incompatible // indirect
	k8s.io/api v0.0.0-20190602205700-9b8cae951d65
	k8s.io/apimachinery v0.0.0-20190602183612-63a6072eb563
)
