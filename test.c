#include <sys/types.h>   
#include <unistd.h>   
#include <stdlib.h>   
#include <stdio.h>   
#include <string.h>
#include <gtk/gtk.h>

GtkWidget *textview1;
GtkWidget *entry1;
GtkWidget *entry2;
GtkWidget *entry3;
GtkWidget *entry4;
GtkWidget *entry5;
GtkWidget *entry6;
GtkTextBuffer *buffer;

void deal_pressed1(GtkButton *button, gpointer user_data)
{   
    gchar *entry_text1;
    gchar *entry_text2;
    gchar *entry_text3;
    gchar *entry_text4;
    gchar *entry_text5;
    gchar *entry_text6;
    entry_text1 = gtk_entry_get_text(GTK_ENTRY(entry1));
    entry_text2 = gtk_entry_get_text(GTK_ENTRY(entry2));
    entry_text3 = gtk_entry_get_text(GTK_ENTRY(entry3));
    entry_text4 = gtk_entry_get_text(GTK_ENTRY(entry4));
    entry_text5 = gtk_entry_get_text(GTK_ENTRY(entry5));
    entry_text6 = gtk_entry_get_text(GTK_ENTRY(entry6));

    char s[30];
    char d[30];
    sprintf(s,"%s",entry_text2);
    sprintf(d,"%s",entry_text3);

    int i;
    for(i=0;i<30;i++){
	if(s[i]=='.') s[i]=' ';
	if(d[i]=='.') d[i]=' ';
    }

    char cmd[100];
    sprintf(cmd,"./proxy insert %s %s %s %s %s %s",entry_text1,s,d,entry_text4,entry_text5,entry_text6);


    FILE   *stream;
    FILE   *wstream;
    char   buf[1024];
    memset( buf, '\0', sizeof(buf) );//初始化buf,以免后面写如乱码到文件中
    stream = popen( cmd, "r" );
    wstream = fopen( "test_popen.txt", "w+"); //新建一个可写的文件
    fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
    printf(buf);
    buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview1));
    gtk_text_buffer_set_text (buffer, (char*)buf, -1);
    fwrite( buf, 1, sizeof(buf), wstream );//将buf中的数据写到FILE    *wstream对应的流中，也是写到文件中
    pclose( stream );
    fclose( wstream );

}

void deal_pressed2(GtkButton *button, gpointer user_data)
{   
    FILE   *stream;
    FILE   *wstream;
    char   buf[1024];
    memset( buf, '\0', sizeof(buf) );//初始化buf,以免后面写如乱码到文件中
    stream = popen( "./proxy refer", "r" );
    wstream = fopen( "test_popen.txt", "w+"); //新建一个可写的文件
    fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
    printf(buf);
    buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview1));
    gtk_text_buffer_set_text (buffer, (char*)buf, -1);
    fwrite( buf, 1, sizeof(buf), wstream );//将buf中的数据写到FILE    *wstream对应的流中，也是写到文件中
    pclose( stream );
    fclose( wstream );
}

void deal_pressed3(GtkButton *button, gpointer user_data)
{
    FILE   *stream;
    FILE   *wstream;
    char   buf[1024];
    memset( buf, '\0', sizeof(buf) );//初始化buf,以免后面写如乱码到文件中
    stream = popen( "./proxy status", "r" );
    wstream = fopen( "test_popen.txt", "w+"); //新建一个可写的文件
    fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
    printf(buf);
    buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview1));
    gtk_text_buffer_set_text (buffer, (char*)buf, -1);
    fwrite( buf, 1, sizeof(buf), wstream );//将buf中的数据写到FILE    *wstream对应的流中，也是写到文件中
    pclose( stream );
    fclose( wstream );
}

void deal_pressed4(GtkButton *button, gpointer user_data)
{   
    gchar *entry_text1;
    entry_text1 = gtk_entry_get_text(GTK_ENTRY(entry1));

    char cmd[100];
    sprintf(cmd,"./proxy delete %s",entry_text1);


    FILE   *stream;
    FILE   *wstream;
    char   buf[1024];
    memset( buf, '\0', sizeof(buf) );//初始化buf,以免后面写如乱码到文件中
    stream = popen( cmd, "r" );
    wstream = fopen( "test_popen.txt", "w+"); //新建一个可写的文件
    fread( buf, sizeof(char), sizeof(buf), stream); //将刚刚FILE* stream的数据流读取到buf中
    printf(buf);
    buffer = gtk_text_view_get_buffer (GTK_TEXT_VIEW (textview1));
    gtk_text_buffer_set_text (buffer, (char*)buf, -1);
    fwrite( buf, 1, sizeof(buf), wstream );//将buf中的数据写到FILE    *wstream对应的流中，也是写到文件中
    pclose( stream );
    fclose( wstream );

}

void deal_pressed5(GtkButton *button, gpointer user_data)
{   
    gchar *entry_text2;
    gchar *entry_text3;
    entry_text2 = gtk_entry_get_text(GTK_ENTRY(entry2));
    entry_text3 = gtk_entry_get_text(GTK_ENTRY(entry3));
//iptables -t nat -A POSTROUTING -s 172.16.86.2 -j SNAT --to 192.168.86.3
    char cmd[100];
    sprintf(cmd,"iptables -t nat -A POSTROUTING -s %s -j SNAT --to %s",entry_text2,entry_text3);
    system(cmd);
}

void deal_pressed6(GtkButton *button, gpointer user_data)
{   
    gchar *entry_text2;
    gchar *entry_text3;
    entry_text2 = gtk_entry_get_text(GTK_ENTRY(entry2));
    entry_text3 = gtk_entry_get_text(GTK_ENTRY(entry3));
//iptables -t nat -A PREROUTING -d 192.168.86.0/24 -j DNAT --to-destination 192.168.86.2
    char cmd[100];
    sprintf(cmd,"iptables -t nat -A PREROUTING -d %s -j DNAT --to-destination %s",entry_text3,entry_text2);
    system(cmd);
}

int main(int argc, char *argv[])
{
	//1.gtk初始化
	gtk_init(&argc,&argv);
 
	//2.创建GtkBuilder对象，GtkBuilder在<gtk/gtk.h>声明
	GtkBuilder *builder = gtk_builder_new();
 
	//3.读取ui.glade文件的信息，保存在builder中
	if ( !gtk_builder_add_from_file(builder,"ui.glade", NULL)) {
		printf("connot load file!");
	}
 
	//4.获取窗口指针，注意"window1"要和glade里面的标签名词匹配
	GtkWidget *window = GTK_WIDGET(gtk_builder_get_object(builder,"window1"));

        GtkWidget *button1 = GTK_BUTTON(gtk_builder_get_object(builder, "button1"));
        GtkWidget *button2 = GTK_BUTTON(gtk_builder_get_object(builder, "button2"));
        GtkWidget *button3 = GTK_BUTTON(gtk_builder_get_object(builder, "button3"));
        GtkWidget *button4 = GTK_BUTTON(gtk_builder_get_object(builder, "button4"));
        GtkWidget *button5 = GTK_BUTTON(gtk_builder_get_object(builder, "button5"));
        GtkWidget *button6 = GTK_BUTTON(gtk_builder_get_object(builder, "button6"));

	textview1 = GTK_WIDGET(gtk_builder_get_object(builder,"textview1"));

	entry1 = GTK_WIDGET(gtk_builder_get_object(builder,"entry1"));
	entry2 = GTK_WIDGET(gtk_builder_get_object(builder,"entry2"));
	entry3 = GTK_WIDGET(gtk_builder_get_object(builder,"entry3"));
	entry4 = GTK_WIDGET(gtk_builder_get_object(builder,"entry4"));
	entry5 = GTK_WIDGET(gtk_builder_get_object(builder,"entry5"));
	entry6 = GTK_WIDGET(gtk_builder_get_object(builder,"entry6"));
 
        //4.创建按钮信号
        g_signal_connect(button1, "clicked", G_CALLBACK( deal_pressed1 ), "haha, button");
        g_signal_connect(button2, "clicked", G_CALLBACK( deal_pressed2 ), "haha, button");
	g_signal_connect(button3, "clicked", G_CALLBACK( deal_pressed3 ), "haha, button");
	g_signal_connect(button4, "clicked", G_CALLBACK( deal_pressed4 ), "haha, button");
	g_signal_connect(button5, "clicked", G_CALLBACK( deal_pressed5 ), "haha, button");
	g_signal_connect(button6, "clicked", G_CALLBACK( deal_pressed6 ), "haha, button");

        //5.显示所控件
        gtk_widget_show_all(window);
 
        //6.主事件循环
        gtk_main();
 
        return 0;

}
