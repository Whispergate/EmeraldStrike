FROM itsafeaturemythic/mythic_python_dotnet:latest
RUN pip3 install mythic_container==0.7.0rc9
RUN pip3 install --upgrade --force-reinstall grpcio>=1.78.0

RUN apt-get clean
RUN dpkg --add-architecture i386

RUN apt-get update \
    && apt-get install -y --no-install-recommends --allow-downgrades \
        ccache clang gcc gcc-multilib nasm \
        mingw-w64 g++-mingw-w64-x86-64 g++-mingw-w64-i686 \
        binutils-mingw-w64 make \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt

ENV CCACHE_DIR=/var/cache/ccache
ENV CCACHE_MAXSIZE=500M

COPY [".", "/Mythic"]
RUN find . -name "*.py" -exec sed -i "s/$//" {} +

WORKDIR /Mythic/

RUN mkdir -p emeraldstrike/agent_code/bin/obj

CMD ["python3", "main.py"]
