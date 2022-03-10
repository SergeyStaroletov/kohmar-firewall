/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#ifndef MYFRAME_H
#define MYFRAME_H

#include "../Common/utils/UnixSemaphore.h"
#include <QDateTime>
#include <QDebug>
#include <QFrame>
#include <QMessageBox>
#include <QPainter>
#include <QScrollArea>
#include <QVBoxLayout>

class AnomalyTcpFrame : public QFrame {
  Q_OBJECT
public:
  explicit AnomalyTcpFrame(QObject *parent = 0, int _anomaly_limit = 40);
  void paintGraphic();
  void addPoint(double y);
  void setLimit(int _limit);
  void clear();

private:
  void paintEvent(QPaintEvent *);
  void drawScale();
  int whatToDraw;
  int curX;
  int anomaly_limit;
  QList<QPoint *> points;
  QDateTime prevTime;
  UnixSemaphore *sem;

signals:

public slots:

protected slots:
  // void draw();
};

#endif // MYFRAME_H
