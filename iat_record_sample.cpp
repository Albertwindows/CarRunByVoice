/*
* 语音听写(iFly Auto Transform)技术能够实时地将语音转换成对应的文字。
*/
#include <stdlib.h>
#include <map>
#include <stdio.h>
#include <windows.h>
#include <conio.h>
#include <errno.h>
#include <process.h>
#include "msp_cmn.h"
#include "msp_errors.h"
#include "./include/speech_recognizer.h"

HANDLE hComm;
OVERLAPPED m_ov;
COMSTAT comstat;
unsigned char d;



std::map<const char*,char> orderSwith;
DWORD WINAPI MyThread1(LPVOID pParam);
DWORD WINAPI MyThread2(LPVOID pParam);
bool ProcessErrorMessage(char* ErrorText);

#define FRAME_LEN	640 
#define	BUFFER_SIZE	4096
char res_str[7] = { 0 };
const char* ode[7] = { "停止。","前进。","后退。","右转。","左转。","逆时针。","顺时针。" };
char       tode[7] = { '0','3','5','8','2','9','6' };
static char *g_result = NULL;
static unsigned int g_buffersize = BUFFER_SIZE;
//#define _DEBUGE
enum{
	EVT_START = 0,
	EVT_STOP,
	EVT_QUIT,
	EVT_TOTAL
};
static HANDLE events[EVT_TOTAL] = {NULL,NULL,NULL};

static COORD begin_pos = {0, 0};
static COORD last_pos = {0, 0};
void init() {
	//0——静止；3——前进；5——后退；8——右转；
	//2——左转；9——逆时针；6——顺时针
	int len = 7;
	const char* ode1[7] = { "停止","前进","后退","右转","左转","逆时针","顺时针" };
	const char* ode2[7] = { "停止。","前进。","后退。","右转。","左转。","逆时针。","顺时针。" };
	
	for (int i = 0; i < len; i++)
	{
		orderSwith[ode1[i]] = tode[i];
		orderSwith[ode2[i]] = tode[i];
	}
}
int getOrder()
{
	int len = 7; int res = 0;
	for (int i = 0; i < len; i++) {
		if (strcmp(res_str, ode[i]) == 0)
			res = tode[i];
	}
	
	if (res<'0' || res >'9')
		return '0';
	else
		return res;
}
bool WriteChar(BYTE* m_szWriteBuffer, DWORD m_nToSend)
{
	BOOL bWrite = TRUE;
	BOOL bResult = TRUE;
	DWORD BytesSent = 0;
	//HANDLE m_hWriteEvent;
	//ResetEvent(m_hWriteEvent);
	if (bWrite)
	{
		m_ov.Offset = 0;
		m_ov.OffsetHigh = 0;
		// Clear buffer
		bResult = WriteFile(hComm,             // Handle to COMM Port
			m_szWriteBuffer, // Pointer to message buffer in calling finction
			m_nToSend,                      // Length of message to send
			&BytesSent,         // Where to store the number of bytes sent
			&m_ov);                    // Overlapped structure
		if (!bResult)
		{
			DWORD dwError = GetLastError();
			switch (dwError)
			{
			case ERROR_IO_PENDING:
			{
				// continue to GetOverlappedResults()
				BytesSent = 0;
				bWrite = FALSE;
				break;
			}
			default:
			{
				// all other error codes
				ProcessErrorMessage("WriteFile()");
			}
			}
		}
	} // end if(bWrite)
	if (!bWrite)
	{
		bWrite = TRUE;
		bResult = GetOverlappedResult(hComm,   // Handle to COMM port
			&m_ov,     // Overlapped structure
			&BytesSent,    // Stores number of bytes sent
			TRUE);         // Wait flag

						   // deal with the error code
		if (!bResult)
		{
			ProcessErrorMessage("GetOverlappedResults() in WriteFile()");
		}
	} // end if (!bWrite)

	  // Verify that the data size send equals what we tried to send
	if (BytesSent != m_nToSend)
	{
		printf("WARNING: WriteFile() error.. Bytes Sent: %d; Message Length: %d\n", BytesSent, strlen((char*)m_szWriteBuffer));
	}
	return true;
}

static void show_result(char *string, char is_over)
{
	if (is_over)
		printf("这里是提前识别的结果：%s\n", string);
	//COORD orig, current;
	//CONSOLE_SCREEN_BUFFER_INFO info;
	//HANDLE w = GetStdHandle(STD_OUTPUT_HANDLE);
	//GetConsoleScreenBufferInfo(w, &info);
	//current = info.dwCursorPosition;

	//if(current.X == last_pos.X && current.Y == last_pos.Y ) {
	//	SetConsoleCursorPosition(w, begin_pos);
	//} else {
	//	/* changed by other routines, use the new pos as start */
	//	begin_pos = current;
	//}
	//if(is_over)
	//	SetConsoleTextAttribute(w, FOREGROUND_GREEN);
	////开始和另外的一个程序进行接口处。
	////printf("--------------------------------\n");
	//printf("这里是提前识别的结果：%s\n", string);
	////printf("--------------------------------\n");
	////if(is_over)
	////	SetConsoleTextAttribute(w, info.wAttributes);

	//GetConsoleScreenBufferInfo(w, &info);
	//last_pos = info.dwCursorPosition;
}

static void show_key_hints(void)
{
	printf("\n\
----------------------------\n\
Press r to start speaking\n\
Press s to end your speaking\n\
Press q to quit\n\
----------------------------\n");
}

/* 上传用户词表 */
static int upload_userwords()
{
	char*			userwords	=	NULL;
	size_t			len			=	0;
	size_t			read_len	=	0;
	FILE*			fp			=	NULL;
	int				ret			=	-1;

	fp = fopen("userwords.txt", "rb");
	if (NULL == fp)										
	{
		printf("\nopen [userwords.txt] failed! \n");
		goto upload_exit;
	}

	fseek(fp, 0, SEEK_END);
	len = ftell(fp); //获取文件大小
	fseek(fp, 0, SEEK_SET);  					
	
	userwords = (char*)malloc(len + 1);
	if (NULL == userwords)
	{
		printf("\nout of memory! \n");
		goto upload_exit;
	}

	read_len = fread((void*)userwords, 1, len, fp); //读取用户词表内容
	if (read_len != len)
	{
		printf("\nread [userwords.txt] failed!\n");
		goto upload_exit;
	}
	userwords[len] = '\0';
	
	MSPUploadData("userwords", userwords, len, "sub = uup, dtt = userword", &ret); //上传用户词表
	if (MSP_SUCCESS != ret)
	{
		printf("\nMSPUploadData failed ! errorCode: %d \n", ret);
		goto upload_exit;
	}
	
upload_exit:
	if (NULL != fp)
	{
		fclose(fp);
		fp = NULL;
	}	
	if (NULL != userwords)
	{
		free(userwords);
		userwords = NULL;
	}
	
	return ret;
}

/* helper thread: to listen to the keystroke */
static unsigned int  __stdcall helper_thread_proc ( void * para)
{
	int key;
	int quit = 0;

	do {
		key = _getch();
		switch(key) {
		case 'r':
		case 'R':
			SetEvent(events[EVT_START]);
			break;
		case 's':
		case 'S':
			SetEvent(events[EVT_STOP]);
			break;
		case 'q':
		case 'Q':
			quit = 1;
			SetEvent(events[EVT_QUIT]);
			PostQuitMessage(0);
			break;
		default:
			break;
		}

		if(quit)
			break;		
	} while (1);

	return 0;
}

static HANDLE start_helper_thread()
{
	HANDLE hdl;

	hdl = (HANDLE)_beginthreadex(NULL, 0, helper_thread_proc, NULL, 0, NULL);

	return hdl;
}

void on_result(const char *result, char is_last)
{
	if (result) {
		/*printf("-----------------\n");
		printf("这里是：on_result\n");
		printf("%s\n", result);
		printf("-----------------\n");*/
		size_t left = g_buffersize - 1 - strlen(g_result);
		size_t size = strlen(result);
		if (left < size) {
			g_result = (char*)realloc(g_result, g_buffersize + BUFFER_SIZE);
			if (g_result)
				g_buffersize += BUFFER_SIZE;
			else {
				printf("mem alloc failed\n");
				return;
			}
		}
		strncat(g_result, result, size);
		//show_result(g_result, is_last);
		if (is_last) {
			static int cnt = 0;
			cnt++;
			printf("最后的识别结果是：%s\n", g_result);
			for (int i = 0; i < 7; i++) res_str[i] = g_result[i];
			d = getOrder();
			printf("%c\n", d);
			WriteChar(&d, 1);
		}
			
	}
}
void on_speech_begin()
{
	if (g_result)
	{
		free(g_result);
	}
	g_result = (char*)malloc(BUFFER_SIZE);
	g_buffersize = BUFFER_SIZE;
	memset(g_result, 0, g_buffersize);

	printf("Start Listening...\n");
}
void on_speech_end(int reason)
{
	if (reason == END_REASON_VAD_DETECT)
		printf("\nSpeaking done \n");
	else
		printf("\nRecognizer error %d\n", reason);
}

/* demo send audio data from a file */
static void demo_file(const char* audio_file, const char* session_begin_params)
{
	unsigned int	total_len = 0;
	int				errcode = 0;
	FILE*			f_pcm = NULL;
	char*			p_pcm = NULL;
	unsigned long	pcm_count = 0;
	unsigned long	pcm_size = 0;
	unsigned long	read_size = 0;
	struct speech_rec iat;
	struct speech_rec_notifier recnotifier = {
		on_result,
		on_speech_begin,
		on_speech_end
	};

	if (NULL == audio_file)
		goto iat_exit;

	f_pcm = fopen(audio_file, "rb");
	if (NULL == f_pcm)
	{
		printf("\nopen [%s] failed! \n", audio_file);
		goto iat_exit;
	}

	fseek(f_pcm, 0, SEEK_END);
	pcm_size = ftell(f_pcm); //获取音频文件大小 
	fseek(f_pcm, 0, SEEK_SET);

	p_pcm = (char *)malloc(pcm_size);
	if (NULL == p_pcm)
	{
		printf("\nout of memory! \n");
		goto iat_exit;
	}

	read_size = fread((void *)p_pcm, 1, pcm_size, f_pcm); //读取音频文件内容
	if (read_size != pcm_size)
	{
		printf("\nread [%s] error!\n", audio_file);
		goto iat_exit;
	}

	errcode = sr_init(&iat, session_begin_params, SR_USER, 0, &recnotifier);
	if (errcode) {
		printf("speech recognizer init failed : %d\n", errcode);
		goto iat_exit;
	}

	errcode = sr_start_listening(&iat);
	if (errcode) {
		printf("\nsr_start_listening failed! error code:%d\n", errcode);
		goto iat_exit;
	}

	while (1)
	{
		unsigned int len = 10 * FRAME_LEN; // 每次写入200ms音频(16k，16bit)：1帧音频20ms，10帧=200ms。16k采样率的16位音频，一帧的大小为640Byte
		int ret = 0;

		if (pcm_size < 2 * len)
			len = pcm_size;
		if (len <= 0)
			break;

		printf(">");
		ret = sr_write_audio_data(&iat, &p_pcm[pcm_count], len);

		if (0 != ret)
		{
			printf("\nwrite audio data failed! error code:%d\n", ret);
			goto iat_exit;
		}

		pcm_count += (long)len;
		pcm_size -= (long)len;		
	}

	errcode = sr_stop_listening(&iat);
	if (errcode) {
		printf("\nsr_stop_listening failed! error code:%d \n", errcode);
		goto iat_exit;
	}

iat_exit:
	if (NULL != f_pcm)
	{
		fclose(f_pcm);
		f_pcm = NULL;
	}
	if (NULL != p_pcm)
	{
		free(p_pcm);
		p_pcm = NULL;
	}

	sr_stop_listening(&iat);
	sr_uninit(&iat);
}

/* demo recognize the audio from microphone */
static void demo_mic(const char* session_begin_params)
{
	int errcode;
	int i = 0;
	HANDLE helper_thread = NULL;

	struct speech_rec iat;
	DWORD waitres;
	char isquit = 0;

	struct speech_rec_notifier recnotifier = {
		on_result,
		on_speech_begin,
		on_speech_end
	};

	errcode = sr_init(&iat, session_begin_params, SR_MIC, DEFAULT_INPUT_DEVID, &recnotifier);
	if (errcode) {
		printf("speech recognizer init failed\n");
		return;
	}

	for (i = 0; i < EVT_TOTAL; ++i) {
		events[i] = CreateEvent(NULL, FALSE, FALSE, NULL);
	}

	helper_thread = start_helper_thread();
	if (helper_thread == NULL) {
		printf("create thread failed\n");
		goto exit;
	}

	show_key_hints();

 	while (1) {
		waitres = WaitForMultipleObjects(EVT_TOTAL, events, FALSE, INFINITE);
		switch (waitres) {
		case WAIT_FAILED:
		case WAIT_TIMEOUT:
			printf("Why it happened !?\n");
			break;
		case WAIT_OBJECT_0 + EVT_START:
			if (errcode = sr_start_listening(&iat)) {
				printf("start listen failed %d\n", errcode);
				isquit = 1;
			}
			break;
		case WAIT_OBJECT_0 + EVT_STOP:		
			if (errcode = sr_stop_listening(&iat)) {
				printf("stop listening failed %d\n", errcode);
				isquit = 1;
			}
			break;
		case WAIT_OBJECT_0 + EVT_QUIT:
			sr_stop_listening(&iat);
			isquit = 1;
			break;
		default:
			break;
		}
		if (isquit)
			break;
	}

exit:
	if (helper_thread != NULL) {
		WaitForSingleObject(helper_thread, INFINITE);
		CloseHandle(helper_thread);
	}
	
	for (i = 0; i < EVT_TOTAL; ++i) {
		if (events[i])
			CloseHandle(events[i]);
	}

	sr_uninit(&iat);
#ifdef _DEBUGE
	printf("----------------\n这里是demo_mic()\n%s\n----------", recnotifier.on_result);
#endif
}


bool ProcessErrorMessage(char* ErrorText)
{
	char *Temp = new char[200];
	LPVOID lpMsgBuf;
	FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL,
		GetLastError(),
		MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), // Default language
		(LPTSTR)&lpMsgBuf,
		0,
		NULL
		);
	sprintf(Temp, "WARNING: %s Failed with the following error: \n%s\nPort: %d\n", (char*)ErrorText, lpMsgBuf, "com2");
	MessageBoxA(NULL, Temp, "Application Error", MB_ICONSTOP);
	LocalFree(lpMsgBuf);
	delete[] Temp;
	return true;
}

bool openport(char *portname)//打开一个串口
{

	hComm = CreateFileA(portname,
		GENERIC_READ | GENERIC_WRITE,
		0,
		0,
		OPEN_EXISTING,
		FILE_FLAG_OVERLAPPED,
		0);
	if (hComm == INVALID_HANDLE_VALUE)
		return FALSE;
	else
		return true;
}

bool setupdcb(int rate_arg)
{
	DCB dcb;
	int rate = rate_arg;
	memset(&dcb, 0, sizeof(dcb));
	if (!GetCommState(hComm, &dcb))//获取当前DCB配置
	{
		ProcessErrorMessage("GetCommState()");
		return FALSE;
	}
	/* -------------------------------------------------------------------- */
	// set DCB to configure the serial port
	dcb.DCBlength = sizeof(dcb);
	/* ---------- Serial Port Config ------- */
	dcb.BaudRate = rate;
	dcb.Parity = NOPARITY;
	dcb.fParity = 0;
	dcb.StopBits = ONESTOPBIT;
	dcb.ByteSize = 8;
	dcb.fOutxCtsFlow = 0;
	dcb.fOutxDsrFlow = 0;
	dcb.fDtrControl = DTR_CONTROL_DISABLE;
	dcb.fDsrSensitivity = 0;
	dcb.fRtsControl = RTS_CONTROL_DISABLE;
	dcb.fOutX = 0;
	dcb.fInX = 0;
	/* ----------------- misc parameters ----- */
	dcb.fErrorChar = 0;
	dcb.fBinary = 1;
	dcb.fNull = 0;
	dcb.fAbortOnError = 0;
	dcb.wReserved = 0;
	dcb.XonLim = 2;
	dcb.XoffLim = 4;
	dcb.XonChar = 0x13;
	dcb.XoffChar = 0x19;
	dcb.EvtChar = 0;
	/* -------------------------------------------------------------------- */
	// set DCB
	if (!SetCommState(hComm, &dcb))
	{
		ProcessErrorMessage("SetCommState()");
		return false;
	}
	else
		return true;
}

bool setuptimeout(DWORD ReadInterval, DWORD ReadTotalMultiplier, DWORD ReadTotalconstant, DWORD WriteTotalMultiplier, DWORD WriteTotalconstant)
{
	COMMTIMEOUTS timeouts;
	timeouts.ReadIntervalTimeout = ReadInterval;
	timeouts.ReadTotalTimeoutConstant = ReadTotalconstant;
	timeouts.ReadTotalTimeoutMultiplier = ReadTotalMultiplier;
	timeouts.WriteTotalTimeoutConstant = WriteTotalconstant;
	timeouts.WriteTotalTimeoutMultiplier = WriteTotalMultiplier;
	if (!SetCommTimeouts(hComm, &timeouts))
	{
		ProcessErrorMessage("SetCommTimeouts()");
		return false;
	}
	else
		return true;
}

bool ReceiveChar()
{
	BOOL bRead = TRUE;
	BOOL bResult = TRUE;
	DWORD dwError = 0;
	DWORD BytesRead = 0;
	char RXBuff;
	for (;;)
	{
		bResult = ClearCommError(hComm, &dwError, &comstat);
		if (comstat.cbInQue == 0)
			continue;
		if (bRead)
		{
			bResult = ReadFile(hComm,      // Handle to COMM port
				&RXBuff,             // RX Buffer Pointer
				1,                   // Read one byte
				&BytesRead,          // Stores number of bytes read
				&m_ov);      // pointer to the m_ov structure
			printf("%c", RXBuff);
			if (!bResult)
			{
				switch (dwError = GetLastError())
				{
				case ERROR_IO_PENDING:
				{
					bRead = FALSE;
					break;
				}
				default:
				{
					break;
				}
				}
			}
			else
			{
				bRead = TRUE;
			}
		} // close if (bRead)
		if (!bRead)
		{
			bRead = TRUE;
			bResult = GetOverlappedResult(hComm,  // Handle to COMM port
				&m_ov,      // Overlapped structure
				&BytesRead,    // Stores number of bytes read
				TRUE);          // Wait flag
		}
	}
}

DWORD WINAPI MyThread1(LPVOID pParam)
{
	ReceiveChar();
	return 0;
}
DWORD WINAPI MyThread2(LPVOID pParam)
{
	while (hComm != INVALID_HANDLE_VALUE)             //串口已被成功打开
	{
		
		d = getOrder();
		printf("%c", d);
		WriteChar(&d, 1);
	}
	return 0;
}

void  blueBegin()
{
	if (openport("com7"))
		printf("open comport success\n");
	if (setupdcb(9600))
		printf("setupDCB success\n");
	if (setuptimeout(0, 0, 0, 0, 0))
		printf("setuptimeout success\n");
	PurgeComm(hComm, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);
	HANDLE hThread1 = CreateThread(NULL, 0, MyThread1, 0, 0, NULL); //读线程
	HANDLE hThread2 = CreateThread(NULL, 0, MyThread2, 0, 0, NULL); //写线程
	CloseHandle(hThread1);
	CloseHandle(hThread2);
}






void openBlue(void)
{
	if (openport("COM7"))
		printf("open comport success\n");
	if (setupdcb(9600))
		printf("setupDCB success\n");
	if (setuptimeout(0, 0, 0, 0, 0))
		printf("setuptimeout success\n");
	PurgeComm(hComm, PURGE_RXCLEAR | PURGE_TXCLEAR | PURGE_RXABORT | PURGE_TXABORT);

}
/* main thread: start/stop record ; query the result of recgonization.
 * record thread: record callback(data write)
 * helper thread: ui(keystroke detection)
 */
int main(int argc, char* argv[])
{
	init();
	openBlue();
	int			ret						=	MSP_SUCCESS;
	int			upload_on				=	1; //是否上传用户词表
	const char* login_params			=	"appid = 5adf20db, work_dir = ."; // 登录参数，appid与msc库绑定,请勿随意改动
	int aud_src = 0;

	/*
	* sub:				请求业务类型
	* domain:			领域
	* language:			语言
	* accent:			方言
	* sample_rate:		音频采样率
	* result_type:		识别结果格式
	* result_encoding:	结果编码格式
	*
	*/
	const char* session_begin_params	=	"sub = iat, domain = iat, language = zh_cn, accent = mandarin, sample_rate = 16000, result_type = plain, result_encoding = gb2312";

	/* 用户登录 */
	ret = MSPLogin(NULL, NULL, login_params); //第一个参数是用户名，第二个参数是密码，均传NULL即可，第三个参数是登录参数	
	if (MSP_SUCCESS != ret)	{
		printf("MSPLogin failed , Error code %d.\n",ret);
		goto exit; //登录失败，退出登录
	}

	printf("开始录音\n");

	demo_mic(session_begin_params);
	//printf("\n########################################################################\n");
	//printf("## 语音听写(iFly Auto Transform)技术能够实时地将语音转换成对应的文字。##\n");
	//printf("########################################################################\n\n");
	//printf("演示示例选择:是否上传用户词表？\n0:不使用\n1:使用\n");

	//scanf("%d", &upload_on);
	//if (upload_on)
	//{
	//	printf("上传用户词表 ...\n");
	//	ret = upload_userwords();
	//	if (MSP_SUCCESS != ret)
	//		goto exit;	
	//	printf("上传用户词表成功\n");
	//}
	
	//printf("音频数据在哪? \n0: 从文件读入\n1:从MIC说话\n");
	//scanf("%d", &aud_src);
	//if(aud_src != 0) {
	//	demo_mic(session_begin_params);
	//} else {
	//	//iflytek02音频内容为“中美数控”；如果上传了用户词表，识别结果为：“中美速控”。;
	//	demo_file("wav/iflytek02.wav", session_begin_params); 
	//}
exit:
	printf("按任意键退出 ...\n");
	_getch();
	MSPLogout(); //退出登录

	return 0;
}