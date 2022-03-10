/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef ADS_QT
#define ADS_QT
#endif

#include "../Common/netlinkmanager.h"
#include "../Common/packsreceiver.h"
#include "../PST/pst_predictor.h"
#include "mainwindow.h"
#include <QApplication>
#include <QDebug>
#include <QMessageBox>
#include <pthread.h>

bool checkModLoaded();

NetLinkManager *nl_mngr = NULL;

int main(int argc, char *argv[]) {
  // pthread_t thread1;
  // int  iret1;
  // Rule * r = new Rule;

  QApplication a(argc, argv);

  /*
      if(checkModLoaded())
      {
          qDebug() << "Module is already loaded!";
      }
      else
      {

          qDebug() << "Module is not loaded! Loading...";//printf ("module is
  not loaded! Loading...\n"); QMessageBox msgBox; msgBox.setText("Module is not
  loaded! Loading..."); msgBox.show();

          //system("insmod ../Common/netfilter.ko");

          if(checkModLoaded())
              qDebug() << "Module loaded!";//printf ("module loaded!\n");
          else {
              qDebug() << "Error! Module not loaded!";
              msgBox.close();
              msgBox.setText("Ошибка! Сетевой экран не запущен!");
              msgBox.exec();
              return 0;
          }
          msgBox.close();
          //qDebug() << "Module is not loaded!";

          return 0;
      }
  */

  qDebug() << "starting pack rcv";
  PacksReceiver *packs_receiver = new PacksReceiver();
  packs_receiver->start();

  qDebug() << "starting netlink man";

  nl_mngr = new NetLinkManager(NETLINK_USERSOCK);

  qDebug() << "start ui";

  MainWindow *w = new MainWindow(0, nl_mngr, packs_receiver);
  w->setWindowFlags(((w->windowFlags() | Qt::CustomizeWindowHint) &
                     ~Qt::WindowMaximizeButtonHint));
  // w->setFixedSize(w->size());
  w->show();

  return a.exec();
}

bool checkModLoaded() {
  FILE *fd = popen("lsmod | grep ads_netfilter", "r");

  char buf[16];

  if (fread(buf, 1, sizeof(buf), fd) >
      0) // if there is some result the module must be loaded
    return true;
  else
    return false;

  return false;
}
