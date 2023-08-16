#!/usr/bin/bash

set -x

dh_clean    # 调用makefile中的clean命令
rm ../*.deb ../*.buildinfo ../*.changes ../*.dsc ../*.xz -rf    # 删除 dpkg-source -b . dh_make --createorig -sy 命令生成的源码压缩包
dh_make --createorig -sy    # 生成debian目录
dpkg-source -b .    # 生成构建源代码包
dpkg-buildpackage -uc -us -j16   # 编译制作deb包
