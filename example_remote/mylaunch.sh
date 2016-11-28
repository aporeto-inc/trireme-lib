docker run \
  --name "Trireme" \
  --privileged \
  --net host \
  -i \
  -t \
  -v /var/run/:/var/run/ \
  -v /tmp:/tmp \
aporeto/trireme-example 
