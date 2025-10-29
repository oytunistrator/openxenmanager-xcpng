#!/bin/bash

# OpenXenManager installation script for system dependencies

set -e

if [ "$EUID" -eq 0 ]; then
    echo "Please do not run as root"
    exit 1
fi

# Detect distribution
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO=$ID
elif [ -f /etc/debian_version ]; then
    DISTRO=debian
elif [ -f /etc/redhat-release ]; then
    DISTRO=redhat
else
    echo "Unsupported distribution"
    exit 1
fi

echo "Detected distribution: $DISTRO"

case $DISTRO in
    ubuntu|debian)
        sudo apt update
        sudo apt install -y python3 python3-gi python3-gi-cairo gir1.2-gtk-3.0 gir1.2-gtk-vnc-1.0 python3-configobj python3-raven
        ;;
    fedora)
        sudo dnf install -y python3 python3-gobject gtk3 python3-configobj python3-raven
        ;;
    centos|rhel)
        sudo yum install -y python3 python3-gobject gtk3 python3-configobj python3-raven
        ;;
    arch)
        sudo pacman -S --noconfirm python python-gobject gtk3 python-configobj python-raven
        ;;
    opensuse)
        sudo zypper install -y python3 python3-gobject gtk3 python3-configobj python3-raven
        ;;
    *)
        echo "Please install manually: Python3, PyGObject, GTK3, configobj, raven"
        exit 1
        ;;
esac

echo "System dependencies installed. Now run 'make install' to install the application."