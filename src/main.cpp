#include "App.h"
#include <QApplication>
#include <QIcon>

int main(int argc, char *argv[]) {
  QApplication app(argc, argv);

  // Set style to Fusion for consistent look across platforms
  app.setStyle("Fusion");

  App window;
  window.setWindowIcon(QIcon(":/message.png"));
  window.show();

  return app.exec();
}
