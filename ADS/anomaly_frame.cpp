/*
 * Anomaly Detection System for network traffic
 * @license GNU GPL
 * @authors Chudov, Staroletov
 */

#include "anomaly_frame.h"

AnomalyTcpFrame::AnomalyTcpFrame(QObject *parent, int _anomaly_limit)
    : QFrame((QWidget *)parent) {
  whatToDraw = 0;
  curX = 5;
  anomaly_limit = _anomaly_limit;

  QPalette palette = this->palette();
  palette.setColor(backgroundRole(), Qt::white);
  this->setPalette(palette);
  this->setAutoFillBackground(true);

  prevTime = QDateTime::currentDateTime();
  sem = new UnixSemaphore();

  /*
  QScrollArea *scroll = new QScrollArea;

  QVBoxLayout *layout = new QVBoxLayout;
  layout->addWidget(scroll);

  this->setLayout(layout);
  */
}

void AnomalyTcpFrame::paintEvent(QPaintEvent *e) {
  switch (whatToDraw) {
  case 0: {
    QPainter p;    // our painter
    p.begin(this); // start painting the widget
    p.setPen(QPen(Qt::black, 1));
    p.drawLine(0, 0, this->width(), 0);
    p.drawLine(0, 0, 0, this->height());
    p.drawLine(this->width() - 1, 0, this->width() - 1, this->height() - 1);
    p.drawLine(0, this->height() - 1, this->width() - 1, this->height() - 1);
    p.setPen(QPen(Qt::red, 1));
    p.drawLine(0, this->height() - anomaly_limit * this->height() / 100,
               this->width() - 1,
               this->height() - anomaly_limit * this->height() / 100);
    p.end(); // painting done

    drawScale();
  } break;

  case 1: {
    QPainter p;    // our painter
    p.begin(this); // start painting the widget
    p.setPen(QPen(Qt::red, 1));
    p.drawLine(0, this->height() - anomaly_limit * this->height() / 100,
               this->width() - 1,
               this->height() - anomaly_limit * this->height() / 100);
    p.setPen(QPen(Qt::black, 1));
    p.drawLine(0, 0, this->width(), 0);
    p.drawLine(0, 0, 0, this->height());
    p.drawLine(this->width() - 1, 0, this->width() - 1, this->height() - 1);
    p.drawLine(0, this->height() - 1, this->width() - 1, this->height() - 1);

    // int width = this->width();
    // int height = this->height();

    p.setPen(QPen(Qt::blue, 1));
    sem->wait();
    for (int i = 0; i < points.count() - 1; i++) {
      // qDebug() << "y = " << QString::number(points[i]->y());
      p.drawLine(points[i]->x(), points[i]->y(), points[i + 1]->x(),
                 points[i + 1]->y());
    }
    sem->post();

    p.end(); // painting done

    drawScale();
  } break;
  }
}

void AnomalyTcpFrame::paintGraphic() {
  whatToDraw = 1;
  update();
}

void AnomalyTcpFrame::addPoint(double y) {
  double yy;
  if (prevTime.msecsTo(QDateTime::currentDateTime()) < 100) { // too fast
    prevTime = QDateTime::currentDateTime();
    return;
  }

  // scroll?
  if (4 * (points.count()) >= this->width()) {
    QPoint *p0 = points.at(0);
    sem->wait();
    points.removeAt(0);
    if (p0)
      delete[] p0;
    sem->post();

    curX -= 4;

    QPoint *p;

    sem->wait();
    foreach (p, points) { p->setX(p->x() - 4); }
    sem->post();
  }

  QPoint *p = new QPoint[2];
  // QPoint p[2];
  p[0].setX(curX);

  int y_percent = (int)(y * this->height()) / 100;

  if (y_percent >= 100)
    yy = 4;
  else
    yy = this->height() - y_percent;

  p[0].setY(yy);

  curX += 2;

  p[1].setX(curX);
  p[1].setY(this->height());

  curX += 2;

  sem->wait();
  points.append(p);
  sem->post();

  prevTime = QDateTime::currentDateTime();
}

void AnomalyTcpFrame::clear() {
  whatToDraw = 0;
  update();
}

void AnomalyTcpFrame::setLimit(int _limit) {
  anomaly_limit = _limit;
  update();
}

void AnomalyTcpFrame::drawScale() {
  QPainter p;    // our painter
  p.begin(this); // start painting the widget
  p.setPen(QPen(Qt::black, 1));
  p.setFont(QFont("Arial", 7, -1, false));

  for (int i = 0; i <= 90; i += 10) {
    p.drawText(2, this->height() - i * this->height() / 100,
               QString::number(i));
  }

  p.drawText(2, 8, QString::number(100));

  p.end(); // painting done
}
