#include "mainwindow.h"
#include "ui_mainwindow.h"

#include <QFile>
#include <QMessageBox>
#include <QDir>
#include <QListWidget>
#include <QListWidgetItem>
#include <QStringList>
#include <QTimer>

#include <QTextStream>
#include <unistd.h>

#include <arpa/inet.h>
#include <stdio.h>  
#include <sys/socket.h> 
#include <netinet/in.h>  
#include <netinet/if_ether.h>  
#include <netinet/ip.h>  
#include <netinet/tcp.h>  
#include <pcap.h>
int a0 = 0, a1 = 0, b0 = 0, b1 = 0;
int CapThread::tcps=0;
tcp_term* CapThread::tcp_list [2000];
bool CapThread::is_capthread_success=true;
QString CapThread::capthread_error_msg="";
int cpu_total1=0,cpu_total2=0;
int cpu_idle1=0,cpu_idle2=0;
QString MainWindow::hex2state(int state){
	switch(state){  
		case 0x1: return QString("ESTABLISHED");  
		case 0x2: return QString("SYN_SENT");  
		case 0x3: return QString("SYN_RECV");  
		case 0x4: return QString("FIN_WAIT1");  
		case 0x5: return QString("FIN_WAIT2");  
		case 0x6: return QString("TIME_WAIT");  
		case 0x7: return QString("CLOSE");  
		case 0x8: return QString("CLOSE_WAIT");  
		case 0x9: return QString("LAST_ACK");  
		case 0xA: return QString("LISTEN");  
		case 0xB: return QString("CLOSING");  
		default: return QString("UNKNOWN");  
	}  
}
void CapThread::cap_handler(unsigned char* argument, const struct pcap_pkthdr* pack,const unsigned char* content){
	struct ether_header *ethernet=(struct ether_header *)content;  
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IP)  {  
		struct iphdr* ip=(struct iphdr*)(content+14);
		if(ip->protocol==6){//we got a tcp package, we only care about this kind
			if(ip->version==4){//this is not tcp6, we do not calculate thems
				struct tcphdr* tcp=(struct tcphdr*)(content+14+20);

				QString addr=QString::number(ip->saddr,16).toUpper();
				int len=8-addr.length();
				for(int i=0;i<len;i++)addr='0'+addr;

				QString port=QString::number(ntohs(tcp->source),16).toUpper();
				len=4-port.length();
				for(int i=0;i<len;i++)port='0'+port;
				QString addpt=addr+':'+port;
				bool exist=0;int i;
				for(i=0;i<tcps;i++){if(tcp_list[i]->addr_port==addpt){exist=1;break;}}
				if(exist)  tcp_list[i]->bytes_new+=pack->len-34;
				else{
					tcp_list[tcps]=new tcp_term;
					tcp_list[tcps]->addr_port=addpt;
					tcp_list[tcps]->bytes_old=0;
					tcp_list[tcps]->bytes_new=pack->len-34;
					tcps++;
				}
			}
		}
	}
}
void CapThread::run(){
	pcap_t* handle;
	pcap_if_t *alldev;
	char error[PCAP_ERRBUF_SIZE];
	char *interface;  
	u_int32_t net_ip;  
	u_int32_t net_mask;  

	if(pcap_findalldevs(&alldev,error)==-1){  
        CapThread::capthread_error_msg=*(new QString("Error out while finding devices\n"));
        CapThread::is_capthread_success=false;
		return ;  
	}
	interface = alldev->name;
	if((handle=pcap_open_live(interface,65535,1,0,error))==NULL) {  
		//parameters of pcap_open_live
		//char* device, name of device
		//int snaplen, the max length of one package
		//int promisc, is mixture mode
		//int to_ms, timeout
		//char* ebuf, to put error info if error out
			 CapThread::capthread_error_msg=*(new QString(error));
			 CapThread::is_capthread_success=false;
			return ;  
		} 
	if(pcap_lookupnet(interface,&net_ip,&net_mask,error)==1){
			 CapThread::capthread_error_msg=*(new QString(error));
			 CapThread::is_capthread_success=false;
			 return;
	}
	//net_ip_addr.s_addr=net_ip;
	//net_mask_addr.s_addr=net_mask;
	pcap_loop(handle,-1,cap_handler,NULL);
	pcap_freealldevs(alldev);
	return;
}
MainWindow::MainWindow(QWidget *parent) : //构造函数，初始化ui，计时器
	QMainWindow(parent),
	ui(new Ui::MainWindow)
{
	is_inodes_updating=false;
	ui->setupUi(this);
	max_inodes=0;
	timer_1000 = new QTimer(this);
	timer_500= new QTimer(this);
	cpthread=new CapThread();

	this->setFixedSize(570,530);
	QWidget::connect( timer_1000, SIGNAL( timeout() ), this, SLOT( timer_update_currentTabInfo() ) );
	QWidget::connect( timer_1000, SIGNAL( timeout() ), this, SLOT( timer_update_dev_bytes() ) );
	QWidget::connect( timer_1000, SIGNAL( timeout() ), this, SLOT( show_tcp_speeds() ));
	QWidget::connect( timer_500,  SIGNAL( timeout() ), this, SLOT( timer_search_socket_inodes() ) );

	QWidget::connect( ui->tabWidget_INFO, SIGNAL( currentChanged() ),
						this, SLOT( on_tabWidget_currentChanged() ) );
	timer_1000->start(1000);
	timer_500->start(500);

	ui->qwtplot_cpu->setAxisScale(QwtPlot::xBottom, 0, 100);
	ui->qwtplot_cpu->setAxisScale(QwtPlot::yLeft, 0,100);
	for(int i=0;i<10;i++)rx_bytes_old[i]=rx_bytes_new[i]=sd_bytes_old[i]=sd_bytes_new[i]=-1;

	for(int i=0;i<100;i++){
		cpu_time[i]=i;
		cpu_val[i]=0;}
	cpu_curve = new QwtPlotCurve();
	cpu_curve->setCurveAttribute(QwtPlotCurve::Fitted, true);

	cpu_curve->attach(ui->qwtplot_cpu);
	cpu_curve->show();
	this->startTimer(1000);

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
	show_tabWidgetInfo(4);

}

MainWindow::~MainWindow()
{
	delete ui;
	delete timer_1000;
	delete timer_500;
}

void MainWindow::timer_update_currentTabInfo()
{
	int index = ui->tabWidget_INFO->currentIndex();
	//定时器只刷新内存tab页面，用于进度条动态显示
	if (index==3||index==4)
		show_tabWidgetInfo(index);
}
void MainWindow::timer_search_socket_inodes(){
	is_inodes_updating=true;
	QDir proc("/proc");
	int pid_start=3;//skip "." and ".."and '\n' added by us
	QString pids=proc.entryList().join("\n");
	int num=0;
	while(1){//loop to see every process

		int fd_start=3;

		int a=pids.indexOf("\n",pid_start);
		int b=pids.indexOf("\n",a+1);
		pid_start=b;

		bool toIntOk;
		QString str_pid=pids.mid(a+1,b-a-1);
		str_pid.toInt(&toIntOk,10);
		if(!toIntOk){break;}

		QDir fd("/proc/"+str_pid+"/fd");
		QString fds=fd.entryList().join("\t");
		QString str_fd;
		QString sockets;

		if(fds==NULL)continue;
		char fd_link[100];
		while(1){//loop to see every file-discriptor
			a=fds.indexOf("\t",fd_start);
			b=fds.indexOf("\t",a+1);
			if(b==-1)break;
			str_fd=fds.mid(a+1,b-a-1);
		
			fd_start=b;
			QByteArray ba=("/proc/"+str_pid+"/fd/"+str_fd).toLatin1();
			
			int len=readlink(ba.data(),fd_link,100);
			fd_link[len]='\0';
			QString link=fd_link;
			if(link.mid(0,6)=="socket"){
				a=link.indexOf('[',0);
				b=link.indexOf(']',a+1);
				QString inode=link.mid(a+1,b-a-1);
				QFile tempFile;
				tempFile.setFileName("/proc/"+str_pid+"/stat");
				if ( !tempFile.open(QIODevice::ReadOnly) ){
					QMessageBox::warning(this, tr("warning"), tr("The pid stat file can not open!"), QMessageBox::Yes);
					return;
				}
				QString tempStr=tempFile.readLine();
				a = tempStr.indexOf("(");
				b = tempStr.indexOf(")");
				tempStr=tempStr.mid(a+1, b-a-1).trimmed();
				socket_list[num]=new socket_term;
																socket_list[num]->pid=str_pid;
																socket_list[num]->pname=tempStr;
																socket_list[num]->inode=inode;
				num++;
			}
		}
	}
	if(num>max_inodes)max_inodes=num;
	is_inodes_updating=false;

}
void MainWindow::timer_update_dev_bytes(){
	QFile tempFile;
	if(ui->tabWidget_INFO->currentIndex()==3)return;
	tempFile.setFileName("/proc/net/dev");
	if(!tempFile.open(QIODevice::ReadOnly)){return;}
	QTextStream netin(&tempFile);
	QString line; 

	int dev_num=-2;
	while(line=netin.readLine(),!line.isNull()){dev_num++;}
	netin.seek(0);
	netin.readLine();
	netin.readLine();

	for(int i=0;i<dev_num;i++){
		line= netin.readLine();
		QChar* src=line.data();
		while(*src!=':'){ if(*src==' '){src++;continue;} src++; }
		src++;
		while(*src==' ')src++;
		if(rx_bytes_old[i]==-1){
			rx_bytes_old[i]=0;
			while(*src!=' '){
				rx_bytes_old[i]*=10;
				rx_bytes_old[i]+=(*src).digitValue();
				src++;
			}
			rx_bytes_new[i]=rx_bytes_old[i];
		}else{
			rx_bytes_old[i]=rx_bytes_new[i];
			rx_bytes_new[i]=0;
			while(*src!=' '){
				rx_bytes_new[i]*=10;
				rx_bytes_new[i]+=(*src).digitValue();
				src++;
			}
		}
		for(int j=0;j<7;j++){//skip several unuseful items
			while(*src==' ')src++;
			while(*src!=' ')src++;
		}
		while(*src==' ')src++;
		if(sd_bytes_old[i]==-1){
			sd_bytes_old[i]=0;
			while(*src!=' '){
				sd_bytes_old[i]*=10;
				sd_bytes_old[i]+=(*src).digitValue();
				src++;
			}
			sd_bytes_new[i]=sd_bytes_old[i];
		}else{
			sd_bytes_old[i]=sd_bytes_new[i];
			sd_bytes_new[i]=0;
			while(*src!=' '){
				sd_bytes_new[i]*=10;
				sd_bytes_new[i]+=(*src).digitValue();
				src++;
			}
		}
	}
	tempFile.close();
}
void MainWindow::show_tcp_speeds(){

	if(ui->tabWidget_INFO->currentIndex()!=3)return;
	
	int tcps=CapThread::tcps;
	double tcp_bytes[tcps];
	for(int i=0;i<tcps;i++) tcp_bytes[i]=CapThread::tcp_list[i]->bytes_new;
	for(int i=0;i<tcps;i++) tcp_bytes[i]=(tcp_bytes[i]-CapThread::tcp_list[i]->bytes_old)/1024;

	while(is_inodes_updating);//wait for inodes info update to finish
		//now we see the speed of every tcp connection
	ui->listWidget_tcpspeed->clear();
	if(CapThread::is_capthread_success==false){
		new QListWidgetItem(CapThread::capthread_error_msg,ui->listWidget_tcpspeed);
		return;
	}
	 new QListWidgetItem(QString::fromUtf8("Local Address:Port\t")+QString::fromUtf8("Remote Address:Port\t")+
                                        QString::fromUtf8("State\t")+QString::fromUtf8("Speed (Kb/s)\t")+QString::fromUtf8("PID/Name"),
										ui->listWidget_tcpspeed);
	QFile tempFile;
	tempFile.setFileName("/proc/net/tcp");
	if(!tempFile.open(QIODevice::ReadOnly)){
		QMessageBox::warning(this, tr("warning"), tr("The tcp file can not open!"), QMessageBox::Yes);
		return ;
	}

	QTextStream tcpin(&tempFile);
	tcpin.readLine();//skip the first line which is table header
	QString line;

	while(line=tcpin.readLine(),!line.isNull()){
		QChar* src=line.data();
		while(*src!=':')src++;src++;//skip the socket number
		while(*src==' ')src++;//and the space
		QString laddr; while(*src!=':'){laddr+=*src;src++;}//local ip address
		src++;
		QString lport; while(*src!=' '){lport+=*src;src++;}//local port
		
		QString addpt=laddr+':'+lport;
		bool exist=0;int index;
		for(index=0;index<tcps;index++){if(CapThread::tcp_list[index]->addr_port==addpt){exist=1;break;}}
		if(exist){
			bool ok;struct  in_addr tmp;
			tmp.s_addr=laddr.toInt(&ok,16);
			QString iaddr=inet_ntoa(tmp);
			
			int port =lport.toInt(&ok,16);
			lport=QString::number(port,10);
			while(!src==' ')src++;
			QString raddr; while(*src!=':'){raddr+=*src;src++;}//remote ip address
			src++;
			QString rport; while(*src!=' '){rport+=*src;src++;}//remote port
			while(*src==' ')src++;
			QString state; while(*src!=' '){state+=*src;src++;}//state
			int ttmp=state.toInt(&ok,16);
			state=hex2state(ttmp);
			
			for(int j=0;j<5;j++){
				while(*src==' ')src++;
				while(*src!=' ')src++;
			}while(*src==' ')src++;
				//skip several fields 
			QString inode;  while(*src!=' '){inode+=*src;src++;}
			bool ie=0;
			
			for(int j=0;j<max_inodes;j++){
				if(socket_list[j]->inode ==inode){
					new QListWidgetItem(laddr+':'+lport+"\t"+raddr+":"+rport+"\t"+state+"\t"
										+QString::number(tcp_bytes[index],'f',3)+'\t'
								+socket_list[j]->pid+'/'+socket_list[j]->pname,ui->listWidget_tcpspeed);
					ie=1;break;
				}
			}
			if(!ie){
				new QListWidgetItem(laddr+':'+lport+"\t"+raddr+':'+rport+'\t'+state+"\t"
										+QString::number(tcp_bytes[index],'f',3)+'\t'
								+""+'/'+"",ui->listWidget_tcpspeed);
			}
			CapThread::tcp_list[index]->bytes_old=tcp_bytes[index];
		}
	}
	tempFile.close();
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

	else if (index==3){	//network informantion

		
		//we first take a snapshot of the list to make it as accurate as possible

		ui->listWidget_devspeed->clear();

		tempFile.setFileName("/proc/net/dev");
		if(!tempFile.open(QIODevice::ReadOnly)){
			QMessageBox::warning(this, tr("warning"), tr("The net device file can not open!"), QMessageBox::Yes);
			return ;
		}
        new QListWidgetItem(QString::fromUtf8("Device Name\t")+QString::fromUtf8("Download Speed\t")
                    +QString::fromUtf8("Upload Speed"),ui->listWidget_devspeed);

		QString line;  
		QTextStream netin(&tempFile);
		int dev_num=-2;
		while(line=netin.readLine(),!line.isNull()){dev_num++;}
		netin.seek(0);
		netin.readLine();
		netin.readLine();

		for(int i=0;i<dev_num;i++){
			line= netin.readLine();
			QString dev_name,rx_speed,sd_speed;
			double speed1=0,speed2=0;
			QChar* src=line.data();
			while(*src!=':'){
				if(*src==' '){src++;continue;}
				dev_name+=*src;src++;
			}
			src++;while(*src==' ')src++;
			if(rx_bytes_old[i]==-1){
				rx_bytes_old[i]=0;
				while(*src!=' '){
					rx_bytes_old[i]*=10;
					rx_bytes_old[i]+=(*src).digitValue();src++;
				}
				rx_bytes_new[i]=rx_bytes_old[i];
				speed1=0;
			}else{
				rx_bytes_old[i]=rx_bytes_new[i];
				rx_bytes_new[i]=0;
				while(*src!=' '){
					rx_bytes_new[i]*=10;
					rx_bytes_new[i]+=(*src).digitValue();src++;
				}
				speed1=rx_bytes_new[i]-rx_bytes_old[i];
			}
			speed1/=1024;

			for(int j=0;j<7;j++){//skip several unuseful items
				while(*src==' ')src++;
				while(*src!=' ')src++;
			}
			while(*src==' ')src++;
			if(sd_bytes_old[i]==-1){
				sd_bytes_old[i]=0;
				while(*src!=' '){
					sd_bytes_old[i]*=10;
					sd_bytes_old[i]+=(*src).digitValue();src++;
				}
				sd_bytes_new[i]=sd_bytes_old[i];
				speed2=0;
			}
			else{
				sd_bytes_old[i]=sd_bytes_new[i];
				sd_bytes_new[i]=0;
				while(*src!=' '){
					sd_bytes_new[i]*=10;
					sd_bytes_new[i]+=(*src).digitValue();src++;
				}
				speed2=sd_bytes_new[i]-sd_bytes_old[i];
			}
			speed2/=1024;
            new QListWidgetItem(dev_name+"\t\t"+rx_speed.setNum(speed1,'f',3)+"\t\t"+
						sd_speed.setNum(speed2,'f',3),ui->listWidget_devspeed);
		}
		tempFile.close();//dev_speed is finished
	//}
		
	}
	else if (index == 4) //系统信息
	{
		//int ok;
		tempFile.setFileName("/proc/cpuinfo"); //打开CPU信息文件
		if ( !tempFile.open(QIODevice::ReadOnly) )
		{
			QMessageBox::warning(this, tr("warning"), tr("The cpuinfo file can not open!"), QMessageBox::Yes);
			return;
		}
        int cores;
        while(1){
            tempStr = tempFile.readLine();
            if( pos = tempStr.indexOf("siblings"), pos!=-1)
            {
                        pos+=11;
                        QString str_cores=tempStr.mid(pos,tempStr.length()-11);
                        cores=str_cores.toInt();
                        ui->label_CPUCores->setText(str_cores);
                        break;
            }
        }
        tempFile.close();
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
			else if (pos = tempStr.indexOf("cache size"), pos!=-1)
			{
				pos += 13; //跳过前面的"cache size："所占用的字符
				QString *cache_size = new QString( tempStr.mid(pos, tempStr.length()-16) );
                int cachesize = cache_size->toInt(); 
                cache_size->setNum(cachesize);
                ui->label_CatheCapacity->setText(*cache_size + " KB * "+tempStr.setNum(cores));
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


		tempFile.close(); //关闭操作系统信息文件
	}


	else{
	}
	return;

}

void MainWindow::on_pushButton_halt_clicked()
{
	
	int status=system("shutdown now -P");
    if(WEXITSTATUS(status)!=0){
        QMessageBox::warning(this,tr("Root user required"),"shutdown: only root user can execute this command.");
	}
}

void MainWindow::on_pushButton_reboot_clicked()
{
    int status=system("reboot");
    if(WEXITSTATUS(status)!=0){
        QMessageBox::warning(this,tr("Root user required"),"reboot: only root user can execute this command.");
    }
}


void MainWindow::on_tabWidget_INFO_currentChanged(int index)
{
	show_tabWidgetInfo(index); //显示tab中的内容
	return ;
}

void MainWindow::on_pushButton_pkill_clicked()
{
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

