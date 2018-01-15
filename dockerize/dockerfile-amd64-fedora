FROM fedora:latest
LABEL vendor="Bayshore Networks" \
	com.bayshorenetworks.version="1.0" \
	com.bayshorenetworks.version.is-production="yes" \
	com.bayshorenetworks.release-date="2017-12-01"
ENV TERM vt102
ENV HOME /yextend
ARG user=bayshore
ARG uid=1000
ARG gid=1000
RUN dnf -y install \
		wget \
		make \
		pkgconf-pkg-config \
		autoconf \
		gcc-c++ \
		libtool \
		zlib-devel \
		bzip2-devel \
		openssl-devel \
		libarchive-devel \
		pcre-devel \
		libuuid-devel \
		poppler-utils \
		python-nose
RUN wget -O /tmp/v3.7.0.tar.gz https://github.com/VirusTotal/yara/archive/v3.7.0.tar.gz && \
	cd /tmp && \
	tar xfz v3.7.0.tar.gz && \
	cd yara-3.7.0 && \
	./bootstrap.sh && \
	./configure --prefix=/usr && \
	make && make install && \
	rm -rf v3.7.0*
ENV YEXTEND_HOME /yextend/
RUN groupadd -g $gid $user && \
	useradd -u $uid -g $gid $user
USER $user
CMD ["/bin/bash"]
