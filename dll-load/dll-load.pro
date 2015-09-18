TEMPLATE = app
CONFIG -= app_bundle
CONFIG -= qt
CONFIG += console

contains(QMAKE_TARGET.arch, x86_64) {
    Debug:DESTDIR=$$(SRC)/heather/build/debug/64
    Release:DESTDIR=$$(SRC)/heather/build/release/64
}
else {
    Debug:DESTDIR=$$(SRC)/heather/build/debug/32
    Release:DESTDIR=$$(SRC)/heather/build/release/32
}

LIBS += -lUser32

SOURCES += main.cc
