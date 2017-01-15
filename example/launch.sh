docker run \
  --name "Trireme" \
  --privileged \
  --net host \
  -t \
  -v /var/run/docker.sock:/var/run/docker.sock \
aporeto/trireme-example
