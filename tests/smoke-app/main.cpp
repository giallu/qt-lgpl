// Smoke test for a qt-lgpl package: builds against it, then checks that the
// libraries load, plugins are found, TLS works and an HTTPS request succeeds.
#include <QApplication>
#include <QByteArray>
#include <QImage>
#include <QJSEngine>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QPainter>
#include <QRegExp>
#include <QSerialPortInfo>
#include <QState>
#include <QStateMachine>
#include <QUiLoader>
#include <QWebSocket>
#include <QSslSocket>
#include <QSvgRenderer>
#include <QTimer>
#include <QtGlobal>
#include <cstdio>

static int failures = 0;

static void check(bool ok, const char *what, const QString &detail = {})
{
    std::printf("%s %s %s\n", ok ? "[ OK ]" : "[FAIL]", what, qPrintable(detail));
    if (!ok)
        ++failures;
}

int main(int argc, char *argv[])
{
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);

    check(true, "Qt version", QString::fromLatin1(qVersion()));

    // QtSvg + the imageformats/platform plugins
    const QByteArray svg = "<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16'>"
                           "<rect width='16' height='16' fill='#ff0000'/></svg>";
    QSvgRenderer renderer(svg);
    QImage image(16, 16, QImage::Format_ARGB32);
    image.fill(Qt::transparent);
    QPainter painter(&image);
    renderer.render(&painter);
    painter.end();
    check(renderer.isValid() && image.pixelColor(8, 8) == QColor(Qt::red), "SVG rendering");

    // QtQml
    QJSEngine engine;
    check(engine.evaluate("6 * 7").toInt() == 42, "JavaScript engine");

    // a few of the add-on modules
    check(QRegExp("^q(t)?$").exactMatch("qt"), "Core5Compat (QRegExp)");
    QStateMachine machine;
    auto *state = new QState(&machine);
    machine.setInitialState(state);
    check(machine.initialState() == state, "StateMachine");
    check(!QUiLoader().availableWidgets().isEmpty(), "UiTools", QString::number(QUiLoader().availableWidgets().size()) + " widgets");
    QWebSocket socket;
    check(socket.state() == QAbstractSocket::UnconnectedState, "WebSockets");
    check(true, "SerialPort", QString::number(QSerialPortInfo::availablePorts().size()) + " ports");

    // TLS backend (OpenSSL is linked into this build)
    check(QSslSocket::supportsSsl(), "TLS support",
          QSslSocket::activeBackend() + " / " + QSslSocket::sslLibraryVersionString());

    // A real HTTPS request
    QNetworkAccessManager nam;
    QNetworkReply *reply = nam.get(QNetworkRequest(QUrl("https://download.qt.io/")));
    QObject::connect(reply, &QNetworkReply::finished, &app, [&] {
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        check(reply->error() == QNetworkReply::NoError, "HTTPS request",
              QString("HTTP %1 %2").arg(status).arg(reply->errorString()));
        app.exit(failures ? 1 : 0);
    });
    QTimer::singleShot(60000, &app, [&] {
        check(false, "HTTPS request", "timed out");
        app.exit(1);
    });
    return app.exec();
}
