docker run \
  --name "Trireme" \
  --privileged \
  --net host \
  -t \
  -v /:/ \
aporeto/trireme-example 
