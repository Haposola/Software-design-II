#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFile>
#include <QMessageBox>
#include <QDir>
#include <QListWidget>
#include <QListWidgetItem>
#include <QStringList>
#include <QTimer>

int cpu_total1=0,cpu_total2=0;
int cpu_idle1=0,cpu_idle2=0;
//
MainWindow::MainWindow(QWidget *parent) : //构造函数，初始化ui，计时器
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    timer = new QTimer(this);
    this->setFixedSize(570,530);
    QWidget::connect( timer, SIGNAL( timeout() ), this, SLOT( timer_update_currentTabInfo() ) );
    QWidget::connect( ui->tabWidget_INFO, SIGNAL( currentChanged() ),
                      this, SLOT( on_tabWidget_currentChanged() ) );
  //  timer->start(1000);

    ui->qwtplot_cpu->setAxisScale(QwtPlot::xBottom, 0, 100);
    ui->qwtplot_cpu->setAxisScale(QwtPlot::yLeft, 0,100);
    //ui->plot->setAxisTitle(QwtPlot::xBottom, "x->");

    for(int i=0;i<100;i++){
        cpu_time[i]=i;
        cpu_val[i]=0;}
    cpu_curve = new QwtPlotCurve();
    cpu_curve->setCurveAttribute(QwtPlotCurve::Fitted, true);
   // curve->setSamples(time,val);
    cpu_curve->attach(ui->qwtplot_cpu);
    cpu_curve->show();
    this->startTimer(1000);

   // ui->listWidget_process->setSortingEnabled(true);

    QStringList  header;

    ui->tableWidget_process->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_process->setColumnWidth(1,150);
    connect(ui->tableWidget_process->horizontalHeader(), SIGNAL(sectionClicked(int)), this, SLOT(onProHeaderClicked(int)));

    ui->tableWidget_model->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidget_model->setColumnWidth(0,199);
    ui->tableWidget_model->setColumnWidth(1,150);
    ui->tableWidget_model->setColumnWidth(2,150);
    connect(ui->tableWidget_model->horizontalHeader(), SIGNAL(sectionClicked(int)), this, SLOT(onModelHeaderClicked(int)));

    show_tabWidgetInfo(0);
    show_tabWidgetInfo(1);
    show_tabWidgetInfo(2);
    show_tabWidgetInfo(3);

}

MainWindow::~MainWindow()
{
    delete ui;
    delete timer;
}



void MainWindow::onProHeaderClicked(int col)
  {
        ui->tableWidget_process->sortByColumn(col);
  }

void MainWindow::onModelHeaderClicked(int col)
  {
        ui->tableWidget_model->sortByColumn(col);
  }

void MainWindow::timerEvent(QTimerEvent *)
{

    //show_tabWidgetInfo(1);
    //show_tabWidgetInfo(2);
    QString tempStr; //读取文件信息字符串
    QFile tempFile; //用于打开系统文件

    float cpu_ratio;
    QString cpu_rate;

        cpu_total1=cpu_total2;cpu_total2=0;
        cpu_idle1=cpu_idle2;cpu_idle2=0;

        tempFile.setFileName("/proc/stat");
        if ( !tempFile.open(QIODevice::ReadOnly) )
        {
            QMessageBox::warning(this, tr("warning"), tr("The stat file can not open!"), QMessageBox::Yes);
            return;
        }
        tempStr = tempFile.readLine();
        for (int i = 0; i < 7; i++)
        {
            cpu_total2 += tempStr.section(" ", i+2, i+2).toInt();
            if(i==3)
               cpu_idle2 +=tempStr.section(" ", i+2, i+2).toInt();
        }
        tempFile.close(); //关闭stat文件
        int m,n;
        n=abs(cpu_total2-cpu_total1);
        m=abs(cpu_idle2-cpu_idle1);
        if(n==0)
            n++;
        cpu_ratio=(float)(n-m)*100/n;
        cpu_rate=QString::number((n-m)*100/n+1);



        ui->label_cpuinfo->setText(cpu_rate+"%");

        for(int i=0;i<100;i++){
            cpu_val[i]=cpu_val[i+1];
        }
        cpu_val[99]=cpu_ratio;
        cpu_curve->setSamples(cpu_time,cpu_val,100);
        ui->qwtplot_cpu->replot();
}

void MainWindow::show_tabWidgetInfo(int index)
{
    QString tempStr; //读取文件信息字符串
    QFile tempFile; //用于打开系统文件
    int pos; //读取文件的位置

    if (index == 0) //内存資源
    {
        tempFile.setFileName("/proc/meminfo"); //打开内存信息文件
        if ( !tempFile.open(QIODevice::ReadOnly) )
        {
            QMessageBox::warning(this, tr("warning"), tr("The meminfo file can not open!"), QMessageBox::Yes);
            return ;
        }
        QString memTotal;
        QString memFree;
        QString swapTotal;
        QString swapFree;

        int nMemTotal=0, nMemFree=0, nSwapTotal=0, nSwapFree=0;

        while (1)
        {
            tempStr = tempFile.readLine();
            pos = tempStr.indexOf("MemTotal");
            if (pos != -1)
            {
                memTotal = tempStr.mid(pos+10, tempStr.length()-13);
                memTotal = memTotal.trimmed();
                nMemTotal = memTotal.toInt()/1024;
            }
            else if (pos = tempStr.indexOf("MemFree"), pos != -1)
            {
                memFree = tempStr.mid(pos+9, tempStr.length()-12);
                memFree = memFree.trimmed();
                nMemFree = memFree.toInt()/1024;
            }
            else if (pos = tempStr.indexOf("SwapTotal"), pos != -1)
            {
                swapTotal = tempStr.mid(pos+11, tempStr.length()-14);
                swapTotal = swapTotal.trimmed();
                nSwapTotal = swapTotal.toInt()/1024;
            }
            else if (pos = tempStr.indexOf("SwapFree"), pos != -1)
            {
                swapFree = tempStr.mid(pos+10,tempStr.length()-13);
                swapFree = swapFree.trimmed();
                nSwapFree = swapFree.toInt()/1024;
                break;
            }
        }

        memFree = QString::number(nMemFree, 10);
        memTotal = QString::number(nMemTotal, 10);
        swapFree = QString::number(nSwapFree, 10);
        swapTotal = QString::number(nSwapTotal, 10);


        ui->label_RAM_Total->setText(memTotal+" MB");
        ui->label_RAM_Free->setText(memFree+" MB");

        ui->label_SWAP_Total->setText(swapTotal+" MB");
        ui->label_SWAP_Free->setText(swapFree+" MB");


        ui->progressBar_RAM->setValue((nMemTotal-nMemFree)*100/nMemTotal);
        ui->progressBar_SWAP->setValue((nSwapTotal-nSwapFree)*100/nSwapTotal);

        tempFile.close(); //关闭内存信息文件


    }

    else if (index == 1) //进程信息
    {
        int iLen = ui->tableWidget_process->rowCount();
        for(int i=0;i<iLen;i++)
        {
         ui->tableWidget_process->removeRow(0);
          }
        QDir qd("/proc");
        QStringList qsList = qd.entryList();
        QString qs = qsList.join("\n");
        QString id_of_pro;
        bool ok;
        int find_start = 3;
        int a, b;
        int number_of_sleep = 0, number_of_run = 0, number_of_zombie = 0;
        int totalProNum = 0; //进程总数
        QString proName; //进程名
        QString proState; //进程状态
        QString proPri; //进程优先级
        QString proMem; //进程占用内存
        int pro_mem;

        //循环读取进程
        while (1)
        {
            //获取进程PID
            a = qs.indexOf("\n", find_start);
            b = qs.indexOf("\n", a+1);
            find_start = b;
            id_of_pro = qs.mid(a+1, b-a-1);
            totalProNum++;
            id_of_pro.toInt(&ok, 10);
            if(!ok)
            {
                break;
            }

            //打开PID所对应的进程状态文件
            tempFile.setFileName("/proc/" + id_of_pro + "/stat");
            if ( !tempFile.open(QIODevice::ReadOnly) )
            {
                QMessageBox::warning(this, tr("warning"), tr("The pid stat file can not open!"), QMessageBox::Yes);
                return;
            }
            tempStr = tempFile.readLine();
            if (tempStr.length() == 0)
            {
                break;
            }
            a = tempStr.indexOf("(");
            b = tempStr.indexOf(")");
            proName = tempStr.mid(a+1, b-a-1);
            proName.trimmed();
            proState = tempStr.section(" ", 2, 2);
            proPri = tempStr.section(" ", 17, 17);
            pro_mem =tempStr.section(" ", 23, 23).toInt()*4;
           // proMem = QString::number(pro_mem,10);

            switch ( proState.at(0).toLatin1() )
            {
                case 'S':   number_of_sleep++; break; //Sleep
                case 'R':   number_of_run++; break; //Running
                case 'Z':   number_of_zombie++; break; //Zombie
                default :   break;
            }

            //ui->tableWidget_process->setItem(0,0, new QTableWidgetItem("A"));

            QTableWidgetItem *pro_id= new QTableWidgetItem();
            pro_id->setData(Qt::DisplayRole, id_of_pro.toInt());
            QTableWidgetItem *pro_pri= new QTableWidgetItem();
            pro_pri->setData(Qt::DisplayRole, proPri.toInt());
            QTableWidgetItem *pro_memory= new QTableWidgetItem();
            pro_memory->setData(Qt::DisplayRole, pro_mem);

            int row= ui->tableWidget_process->rowCount();
            ui->tableWidget_process->insertRow(row);
            ui->tableWidget_process->setItem(row,0,pro_id);
            ui->tableWidget_process->setItem(row,1,new QTableWidgetItem(proName));
            ui->tableWidget_process->setItem(row,2, new QTableWidgetItem(proState));
            ui->tableWidget_process->setItem(row,3,pro_pri);
            ui->tableWidget_process->setItem(row,4, pro_memory);

             tempFile.close(); //关闭该PID进程的状态文件
        }
        QString temp;
        temp = QString::number(totalProNum, 10);
        ui->label_pNum->setText(temp);
        temp = QString::number(number_of_run, 10);
        ui->label_pRun->setText(temp);
        temp = QString::number(number_of_sleep, 10);
        ui->label_pSleep->setText(temp);
        temp = QString::number(number_of_zombie, 10);
        ui->label_pZombie->setText(temp);


    }

    else if (index == 2) //模块信息
    {
        int iLen = ui->tableWidget_model->rowCount();
        for(int i=0;i<iLen;i++)
        {
         ui->tableWidget_model->removeRow(0);
          }

        tempFile.setFileName("/proc/modules"); //打开模块信息文件
        if ( !tempFile.open(QIODevice::ReadOnly) )
        {
            QMessageBox::warning(this, tr("warning"), tr("The modules file can not open!"), QMessageBox::Yes);
            return ;
        }

        QString mod_Name, mod_Mem, mod_Num;
        //循环读取文件内容，查找需要的信息
        while (1)
        {
            tempStr = tempFile.readLine();
            if (tempStr.length() == 0)
            {
                break;
            }
            mod_Name = tempStr.section(" ", 0, 0);
            mod_Mem = tempStr.section(" ", 1, 1);
            mod_Num = tempStr.section(" ", 2, 2);

            QTableWidgetItem *mod_mem= new QTableWidgetItem();
            mod_mem->setData(Qt::DisplayRole, mod_Mem.toInt());
            QTableWidgetItem *mod_num= new QTableWidgetItem();
            mod_num->setData(Qt::DisplayRole, mod_Num.toInt());

            int row= ui->tableWidget_model->rowCount();
            ui->tableWidget_model->insertRow(row);
            ui->tableWidget_model->setItem(row,0,new QTableWidgetItem(mod_Name));
            ui->tableWidget_model->setItem(row,1, mod_mem);
            ui->tableWidget_model->setItem(row,2, mod_num);

        }
        tempFile.close(); //关闭模块信息文件
    }

    else if (index == 3) //系统信息
    {
        //int ok;
        tempFile.setFileName("/proc/cpuinfo"); //打开CPU信息文件
        if ( !tempFile.open(QIODevice::ReadOnly) )
        {
            QMessageBox::warning(this, tr("warning"), tr("The cpuinfo file can not open!"), QMessageBox::Yes);
            return;
        }

        //循环读取文件内容，查找需要的信息
        while (1)
        {
            tempStr = tempFile.readLine();
            pos = tempStr.indexOf("model name");
            if (pos != -1)
            {
                pos += 13; //跳过前面的"model name："所占用的字符
                QString *cpu_name = new QString( tempStr.mid(pos, tempStr.length()-13) );
                ui->label_CPUName->setText(*cpu_name);
            }
            else if (pos = tempStr.indexOf("vendor_id"), pos != -1)
            {
                pos += 12; //跳过前面的"vendor_id："所占用的字符
                QString *cpu_type = new QString( tempStr.mid(pos, tempStr.length()-12) );
                ui->label_CPUType->setText(*cpu_type);
            }
            else if (pos = tempStr.indexOf("cpu MHz"), pos != -1)
            {
                pos += 11; //跳过前面的"cpu MHz："所占用的字符
                QString *cpu_frq = new QString( tempStr.mid(pos, tempStr.length()-11) );
                double cpufrq = cpu_frq->toDouble(); //4核CPU
                cpu_frq->setNum(cpufrq*4);
                ui->label_CPUFrequency->setText(*cpu_frq + " HZ");
            }
            else if (pos = tempStr.indexOf("cache size"), pos!=-1)
            {
                pos += 13; //跳过前面的"cache size："所占用的字符
                QString *cache_size = new QString( tempStr.mid(pos, tempStr.length()-16) );
                int cachesize = cache_size->toInt(); //4核CPU
                cache_size->setNum(cachesize*4);
                ui->label_CatheCapacity->setText(*cache_size + " KB");
                break;
            }
            else //跳过其他的内容
            {

            }
        }
        tempFile.close(); //关闭CPU信息文件

        //打开操作系统信息文件
        tempFile.setFileName("/proc/version");
        if ( !tempFile.open(QIODevice::ReadOnly) )
        {
            QMessageBox::warning(this, tr("warning"), tr("The version file can not open!"), QMessageBox::Yes);
            return ;
        }
        tempStr = tempFile.readLine();
        pos = tempStr.indexOf("version");
        QString *os_version = new QString( tempStr.mid(0, pos-1) );
        ui->label_SystemType->setText(*os_version);

        int pos1 = tempStr.indexOf("(");
        QString *os_type = new QString( tempStr.mid(pos, pos1-pos-1) );
        ui->label_SystemVersion->setText(*os_type);

        pos = tempStr.indexOf("gcc version");
        pos1 = tempStr.indexOf("#");
        QString *gcc_info = new QString( tempStr.mid(pos+12, pos1-pos-14) );
        ui->label_GCCVersion->setText(*gcc_info);

        tempFile.close(); //关闭操作系统信息文件
    }

    else //说明
    {
    }
    return;
}

void MainWindow::on_pushButton_halt_clicked()
{
    system("halt");
}

void MainWindow::on_pushButton_reboot_clicked()
{
    system("reboot");
}


void MainWindow::on_tabWidget_INFO_currentChanged(int index)
{
    show_tabWidgetInfo(index); //显示tab中的内容
    return ;
}

void MainWindow::on_pushButton_pkill_clicked()
{
    //获得进程号
    int row=ui->tableWidget_process->currentRow();
    QString pro= ui->tableWidget_process->item(row, 0)->text();
    system("kill "+pro.toLatin1());
    QMessageBox::warning(this, tr("kill"), QString::fromUtf8("process killed!"), QMessageBox::Yes);

    show_tabWidgetInfo(1);
}

void MainWindow::on_pushButton_prefresh_clicked()
{
    show_tabWidgetInfo(1);
}

void MainWindow::on_pushButton_Model_refresh_clicked()
{
    show_tabWidgetInfo(2);
}
