# Training image (tickets 09-10): CPU only. Build from repo root:
#   docker build -t wantimpres26-train -f services/model-inference/train/Dockerfile services/model-inference
FROM python:3.11-slim
RUN pip install --no-cache-dir torch==2.4.1 --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir transformers==4.44.2 onnx==1.16.2 onnxruntime==1.19.2 tokenizers==0.19.1 numpy==1.26.4 \
      sentencepiece==0.2.0 protobuf==5.28.2
WORKDIR /work
