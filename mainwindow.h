#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <qwt_plot.h>
#include <qwt_plot_curve.h>
#include <qthread.h>
#include <qstring.h>
namespace Ui {
class MainWindow;
}
typedef struct {
	QString pid;
	QString pname;
	QString inode;
} socket_term;
typedef struct 
{
	QString addr_port;
	int bytes_old;
	int bytes_new;
}tcp_term;
class MainWindow : public QMainWindow
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget *parent = 0);
	~MainWindow();
	class CapThread* cpthread;
private:
	Ui::MainWindow *ui;
	QTimer *timer_1000;
	QTimer *timer_500;
	int rx_bytes_old[10];
	int rx_bytes_new[10];
	int sd_bytes_old[10];
	int sd_bytes_new[10];
	socket_term* socket_list[3000];

	bool is_inodes_updating;
	
	QString hex2state(int state);
	int max_inodes;
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

	void timer_search_socket_inodes();
	void timer_update_currentTabInfo();
	void timer_update_dev_bytes();
		//显示tab中的内容
	void show_tabWidgetInfo(int index);
	void show_tcp_speeds();

	
	void timerEvent(QTimerEvent *);
	void onProHeaderClicked(int col);
	void onModelHeaderClicked(int col);
};

class CapThread : public QThread{

public:
	explicit CapThread(){
		tcps=0;
		is_capthread_success=true;
        capthread_error_msg="";
    };
	static int tcps;
	static tcp_term* tcp_list[2000];
	static bool is_capthread_success;
	static QString capthread_error_msg;
	static void cap_handler(unsigned char* argument, const struct pcap_pkthdr* pack,const unsigned char* content);
	virtual void run();

};

#endif // MAINWINDOW_H
