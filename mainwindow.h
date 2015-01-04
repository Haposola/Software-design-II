#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <qwt_plot.h>
#include <qwt_plot_curve.h>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT
    
public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
    
private:
    Ui::MainWindow *ui;
    QTimer *timer;
    double cpu_val[100];
    double cpu_time[100];

    QwtPlotCurve * cpu_curve;


private slots:
    void on_pushButton_pkill_clicked();
    void on_pushButton_prefresh_clicked();
    void on_pushButton_Model_refresh_clicked();
    void on_pushButton_reboot_clicked();
    void on_pushButton_halt_clicked();
    void on_tabWidget_INFO_currentChanged(int index);
        //显示tab中的内容
    void show_tabWidgetInfo(int index);

     void timerEvent(QTimerEvent *);
     void onProHeaderClicked(int col);
     void onModelHeaderClicked(int col);


};

#endif // MAINWINDOW_H
