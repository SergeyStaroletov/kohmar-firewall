#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMessageBox>
#include <QSystemTrayIcon>
#include <QCloseEvent>
#include "samplesom.h"
#include "selforganizedmap.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    //void setVisible(bool visible);
    
private slots:
    void on_pushButton_clicked();
    void on_table_cellClicked(int row, int column);
    void on_pushButton_2_clicked();
    //void iconActivated(QSystemTrayIcon::ActivationReason reason);

    void on_table_cellActivated(int row, int column);

private:
    void loadToRecognizeVector();
    //void createActions();
    //void createTrayIcon();

protected:
    //void closeEvent(QCloseEvent *);

private:
    Ui::MainWindow *ui;
    QList<SampleSom*> list;
    SelfOrganizedMap * som;
    SampleSom * toRecognize;
    int N;
    int M;
    int dimension;
    int Iters;
    double Radius;
    double G;
    double lambda;
    double eta;

    //QAction *minimizeAction;
    //QAction *maximizeAction;
    //QAction *restoreAction;
    //QAction *quitAction;

    //QSystemTrayIcon *trayIcon;
    //QMenu *trayIconMenu;
};

#endif // MAINWINDOW_H
