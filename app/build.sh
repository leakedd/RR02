#!/bin/bash
# Build de l'app RR02 (aucun projet Xcode : un seul fichier Swift)
set -e
cd "$(dirname "$0")"
APP="RR02.app"
rm -rf "$APP" RR02Radar.app RadarApp.swift
mkdir -p "$APP/Contents/MacOS"
cp Info.plist "$APP/Contents/Info.plist"
swiftc -O -framework Cocoa -framework WebKit RR02App.swift -o "$APP/Contents/MacOS/RR02"
echo "build ok -> $(pwd)/$APP"
