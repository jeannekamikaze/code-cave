TEMPLATE = app
CONFIG -= app_bundle
CONFIG -= qt

Debug:DESTDIR=$$(SRC)/heather/build/debug
Release:DESTDIR=$$(SRC)/heather/build/release

LIBS += -lUser32

SOURCES += main.cc
