FROM python:3.12-slim
WORKDIR /app

RUN pip install --no-cache-dir grpcio grpcio-tools

COPY test.proto server.py client.py ./
# Generate the protobuf/gRPC stubs against the image's own grpcio version.
RUN python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. test.proto

ENTRYPOINT ["python", "-u"]
