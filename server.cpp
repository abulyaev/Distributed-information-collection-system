#define _CRT_SECURE_NO_WARNINGS

#include <WinSock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <iostream>
#include <stdlib.h>
#include <time.h>
#include <Aclapi.h>
#include <Sddl.h>

#include <Mswsock.h>



#define PORT (555)
#define MAX_CLIENTS  (100)


void ServClient(DWORD idx);

#pragma comment (lib, "ws2_32.lib")
#pragma comment (lib, "mswsock.lib")
#pragma warning(disable : 4996)

int count_client = 0;

struct client_ctx
{
	int socket;

	/*unsigned*/ char buf_recv[1024];  // Буфер приема 
	unsigned int sz_recv;      // Принято данных 

	/*unsigned*/ char buf_send[1024];  // Буфер отправки 
	unsigned int sz_send_total;   // Данных в буфере отправки 
	unsigned int sz_send;      // Данных отправлено 

	HCRYPTKEY hSessionKey;

							   // Структуры OVERLAPPED для уведомлений о завершении 
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;

	DWORD flags_recv; // Флаги для WSARecv 
};

// Прослушивающий сокет и все сокеты подключения хранятся  
// в массиве структур (вместе с overlapped и буферами) 
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

// Функция стартует операцию чтения из сокета 
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;

	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv,
		&g_ctxs[idx].overlap_recv, NULL);
}

void schedule_write(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send;
	buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;

	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

void help_for_write(DWORD idx, char * buf, int size)
{
	memcpy(g_ctxs[idx].buf_send, buf, size);
	g_ctxs[idx].sz_send_total = size;
	g_ctxs[idx].sz_send = 0;

	schedule_write(idx);
}

// Функция добавляет новое принятое подключение клиента 
void add_accepted_connection()
{
	DWORD i;
	// Поиск места в массиве g_ctxs для вставки нового подключения 
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;

			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv,
				sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16,
				(struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **)
				&remote_addr, &remote_addr_sz);

			if (remote_addr)
				ip = ntohl(remote_addr->sin_addr.s_addr);

			printf(" connection %u created, remote IP: %u.%u.%u.%u\n",
				i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip)& 0xff
				);

			g_ctxs[i].socket = g_accepted_socket;

			// Bind socket with IOCP port. We use array index as the key.
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i,
				0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}


			HCRYPTPROV hProv;
			HCRYPTKEY hKey;
			HCRYPTKEY hPubKey;
			HCRYPTKEY hPrivKey;
			HCRYPTKEY hSessionKey;

			/*

			MS_ENHANCED_PROV:
				The Microsoft Enhanced Cryptographic Provider, 
					called the Enhanced Provider, 
					supports the same capabilities as the Microsoft Base Cryptographic Provider, 
					called the Base Provider. The Enhanced Provider supports stronger security 
					through longer keys and additional algorithms. 
				It can be used with all versions of CryptoAPI.
			
			PROV_RSA_FULL:
				The PROV_RSA_FULL provider type supports both digital signatures and data encryption. 
				It is considered a general purpose CSP. 
				The RSA public key algorithm is used for all public key operations.
			
			*/

			if (!CryptAcquireContext(&hProv, NULL, MS_ENHANCED_PROV, PROV_RSA_FULL, 0))
			{
				printf("Can't create a context\n");
			}

			if (!CryptGenKey(hProv, AT_KEYEXCHANGE, 1024 << 16, &hKey)) // generate 1024-bit key
			{
				printf("Can't to create a RSA key for exchange\n");
				//success = FALSE;
			}
			else
			{
				printf("RSA key successfully created\n");
			}

			if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPubKey)) // get public user key 
			{
				printf("Can't get the public key from container\n");
				CryptReleaseContext(hProv, 0);
			}

			DWORD pubLen = 0;
			//export public key
			//get array len for export key, len in publen
			if (!CryptExportKey(hPubKey, 0, PUBLICKEYBLOB, 0, NULL, &pubLen))
				std::cout << "CryptExportKey error\n" << std::endl;

			// Init the array used for export the key.
			//BYTE * pubdata = static_cast<BYTE*>(malloc(pubLen));
			BYTE * pubdata = (BYTE*)(malloc(pubLen));
			ZeroMemory(pubdata, pubLen);

			char sessdata[1024];
			char size[1024];
			char buf[1024];
			int len;

			// Export the decryption key.
			if (!CryptExportKey(hPubKey, 0, PUBLICKEYBLOB, 0, (BYTE*)pubdata, &pubLen))   // The data consist our key.
			{
				std::cout << "CryptExportKey error\n" << std::endl;
			}
			else
			{
				std::cout << "The public key successfully exported\n" << std::endl;
			}

			itoa((int)pubLen, size, 10);

			

			memcpy(g_ctxs[i].buf_send, (char*)size, sizeof(size));
			g_ctxs[i].sz_send_total = sizeof(size);
			g_ctxs[i].sz_send = 0;

			//Send the length of the key.
			schedule_write(i);

			memcpy(g_ctxs[i].buf_send, (char*)pubdata, pubLen);
			g_ctxs[i].sz_send_total = pubLen;
			g_ctxs[i].sz_send = 0;

			//Send  the public key to the client.
			schedule_write(i);

			Sleep(1000);

			//Get the session key from client.
			schedule_read(i);

			//sprintf(buf, "%s", g_ctxs[i].buf_recv);

			memcpy(buf, g_ctxs[i].buf_recv, sizeof(g_ctxs[i].buf_recv));

			//recv(my_sock, (char *)&buf, sizeof(buf), 0); 
			len = atoi(buf);

			//Get encrypted session key.
			schedule_read(i);

			memcpy(sessdata, g_ctxs[i].buf_recv, sizeof(g_ctxs[i].buf_recv));

			//sprintf(sessdata, "%s", g_ctxs[i].buf_recv);

			//recv(my_sock, (char *)&sessdata, len, 0);

			if (!CryptGetUserKey(hProv, AT_KEYEXCHANGE, &hPrivKey)) //Get the private user key.
			{
				std::cout << "Can't get the private key from container\n" << std::endl;
				CryptReleaseContext(hProv, 0);
			}

			if (!CryptImportKey(hProv, (BYTE*)sessdata, len, hPrivKey, 0, &hSessionKey)) //Decrypted the session key.
			{
				std::cout << "CryptImportKey error" << std::endl;
			}
			else
			{
				//memcpy((HCRYPTKEY*)g_ctxs[i].hSessionKey, (HCRYPTKEY*)hSessionKey, sizeof(hSessionKey));
				g_ctxs[i].hSessionKey = hSessionKey;
				std::cout << "Session key was successfully importes" << std::endl;
			}

			//Waiting the data from socket.
			schedule_read(i);
			return;
		}
	}

	//The server doesnt fount any connection for client. Couldnt accept.
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

//The function started the acception connection.
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов) 
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));

	// Принятие подключения.  

	// Как только операция будет завершена - порт завершения пришлет уведомление.  
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0,
		sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL,
		&g_ctxs[0].overlap_recv);
}

int init()
{
#ifdef _WIN32 
	// Для Windows следует вызвать WSAStartup перед началом использования сокетов 
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
#endif 
}

void deinit()
{
#ifdef _WIN32 
	// Для Windows следует вызвать WSACleanup в конце работы  
	WSACleanup();
#endif 
}

int sock_err(const char* function, int s)
{
	int err;
#ifdef _WIN32 
	err = WSAGetLastError();
#endif 

	fprintf(stderr, "%s: socket error: %d\n", function, err);
	return -1;
}

void s_close(int s)
{
#ifdef _WIN32 
	closesocket(s);
#endif 
}

void GetOSVersion(char * ver)
{
	OSVERSIONINFOEX osvi;
	BOOL bOsVersionInfoEx;
	ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));

	osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
	bOsVersionInfoEx = GetVersionEx((OSVERSIONINFO *)&osvi);

	if (bOsVersionInfoEx)
	{
		if (osvi.dwMajorVersion == 5)
		{
			if (osvi.dwMinorVersion == 0)
				strcpy(ver, "Microsoft Windows 2000 ");
			if (osvi.dwMinorVersion == 1)
				strcpy(ver, "Microsoft Windows XP");
			if (osvi.dwMinorVersion == 2 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows XP Professional x64 Edition ");
			if (osvi.dwMinorVersion == 2 && GetSystemMetrics(SM_SERVERR2) != 0)
				strcpy(ver, "Microsoft Server 2003 R2");
			if (osvi.dwMinorVersion == 2 && GetSystemMetrics(SM_SERVERR2) == 0)
				strcpy(ver, "Microsoft Server 2003 ");
			if (osvi.dwMinorVersion == 2 && osvi.wSuiteMask & VER_SUITE_WH_SERVER)
				strcpy(ver, "Microsoft Windows Home Server");
		}
		else if (osvi.dwMajorVersion == 6)
		{
			if (osvi.dwMinorVersion == 0 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Vista");
			if (osvi.dwMinorVersion == 0 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Server 2008 ");
			if (osvi.dwMinorVersion == 1 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Server 2008 R2 ");
			if (osvi.dwMinorVersion == 1 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows 7 ");
			if (osvi.dwMinorVersion == 2 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows Server 2012 ");
			if (osvi.dwMinorVersion == 2 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Microsoft Windows 8 ");
			if (osvi.dwMinorVersion == 3 && osvi.wProductType != VER_NT_WORKSTATION)
				strcpy(ver, "Windows Server 2012 R2 ");
			if (osvi.dwMinorVersion == 3 && osvi.wProductType == VER_NT_WORKSTATION)
				strcpy(ver, "Windows Server 8.1 ");
		}
		else if (osvi.dwMajorVersion == 10)
		{
			if (osvi.dwMinorVersion == 0)
				strcpy(ver, "Microsoft Windows 10 ");
		}
		if (osvi.wSuiteMask & VER_SUITE_PERSONAL)
			strcat(ver, " Home Edition ");
		else
			strcat(ver, " Professional ");
	}
}

void io_serv()
{
	init();

	struct sockaddr_in addr;

	// Создание сокета прослушивания 
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);

	// Создание порта завершения 
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}

	// Обнуление структуры данных для хранения входящих соединений 
	memset(g_ctxs, 0, sizeof(g_ctxs));

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(PORT);

	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n");
		return;
	}

	printf("Listening: %hu\n", ntohs(addr.sin_port));

	// Присоединение существующего сокета s к порту io_port.  
	// В качестве ключа для прослушивающего сокета используется 0 
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{

		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}

	g_ctxs[0].socket = s;

	// Старт операции принятия подключения. 
	schedule_accept();

	// Бесконечный цикл принятия событий о завершенных операциях 
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;

		// Ожидание событий в течение 1 секунды 
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap,
			INFINITE);
		if (b)
		{
			// Поступило уведомление о завершении операции 
			if (key == 0) // ключ 0 - для прослушивающего сокета 
			{
				g_ctxs[0].sz_recv += transferred;

				// Принятие подключения и начало принятия следующего 
				add_accepted_connection();
				schedule_accept();

			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента.  
				// Ключ key - индекс в массиве g_ctxs 

				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					int len;
					char buffer;
					buffer = g_ctxs[key].buf_recv[0];
					if (buffer == '1')
					{
						printf("Type and version of OS...\n");
						
						char version[1024];
						GetOSVersion(version);
						
						DWORD count = strlen(version) + 1;
						if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)version, &count, count))
						{
							printf("Encrypt: ERROR!\n");
						}

						help_for_write(key, version, count);
						//send(g_ctxs[key].socket, version, count, 0);
						//schedule_write(key);

						buffer = '0';
						//g_ctxs[key].buf_recv[0] = '\0';
						schedule_read(key);
					}
					else if (buffer == '2')
					{
						printf("Current OS time...\n");

						time_t t;
						struct tm * local_t;
						char clock[256];

						t = time(0);
						local_t = localtime(&t);
						strftime(clock, 256, "%d:%m:%Y %H:%M:%S\n", local_t);

						DWORD count = strlen(clock) + 1;
						if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)clock, &count, count))
						{
							printf("Encrypt: ERROR!\n");
						}
						//send(my_sock, clock, count, 0);
						//send(g_ctxs[key].socket, clock, count, 0);
						//schedule_write(key);
						help_for_write(key, clock, count);
						buffer = '0';
						schedule_read(key);
					}
					else if (buffer == '3')
					{
						printf("Time since OS started...\n");
						
						char time[256];
						DWORD t = GetTickCount();
						_itoa(int(t), time, 10);

						DWORD count = strlen(time) + 1;
						if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)time, &count, count))
						{
							printf("Encrypt: ERROR!\n");
						}
						//send(g_ctxs[key].socket, time, count, 0);

						help_for_write(key, time, count);

						buffer = '0';
						schedule_read(key);
					}
					else if (buffer == '4')
					{
						/// https://msdn.microsoft.com/ru-ru/library/windows/desktop/aa366589(v=vs.85).aspx
						printf("Information about using memory...\n");

						char out_buf[8192];
						ZeroMemory(&out_buf, sizeof(out_buf));
						
						MEMORYSTATUSEX statex;
						char answer[1024];
						
						//GlobalMemoryStatusEx(&statex);
						statex.dwLength = sizeof(statex);
						GlobalMemoryStatusEx(&statex);
						
						_itoa((int)statex.dwMemoryLoad, answer, 10);
						strcat(out_buf, "Percent of memory in use: ");
						strcat(out_buf, answer);
						strcat(out_buf, "\n");
						ZeroMemory(&answer, sizeof(answer));
						
						_i64toa(statex.ullTotalPhys / (1024 * 1024), answer, 10);
						strcat(out_buf, "Total MB of physical memory: ");
						strcat(out_buf, answer);
						strcat(out_buf, "\n");
						ZeroMemory(&answer, sizeof(answer));
						
						_i64toa(statex.ullAvailPhys / (1024 * 1024), answer, 10);
						strcat(out_buf, "Free MB of physical memory: ");
						strcat(out_buf, answer);
						strcat(out_buf, "\n");
						ZeroMemory(&answer, sizeof(answer));
						
						_i64toa(statex.ullTotalPageFile / (1024 * 1024), answer, 10);
						strcat(out_buf, "Total MB of paging file: ");
						strcat(out_buf, answer);
						strcat(out_buf, "\n");
						ZeroMemory(&answer, sizeof(answer));
						
						_i64toa(statex.ullAvailPageFile / (1024 * 1024), answer, 10);
						strcat(out_buf, "Free MB of paging file: ");
						strcat(out_buf, answer);
						strcat(out_buf, "\n");
						ZeroMemory(&answer, sizeof(answer));
						
						_i64toa(statex.ullTotalVirtual / (1024 * 1024), answer, 10);
						_i64toa(statex.ullAvailPageFile / (1024 * 1024), answer, 10);
						strcat(out_buf, "Total MB of virtual memory: ");
						strcat(out_buf, answer);
						strcat(out_buf, "\n");
						ZeroMemory(&answer, sizeof(answer));
						
						_i64toa(statex.ullAvailVirtual / (1024 * 1024), answer, 10);
						strcat(out_buf, "Free MB of virtual memory: ");
						strcat(out_buf, answer);
						strcat(out_buf, "\n");
						ZeroMemory(&answer, sizeof(answer));
						
						DWORD count = strlen(out_buf) + 1;
						if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)out_buf, &count, count))
						{
							printf("Encrypt: ERROR!\n");
						}
						//send(g_ctxs[key].socket, out_buf, count, 0);
						
						help_for_write(key, out_buf, count);

						buffer = '0';
						schedule_read(key);
					}
					else if (buffer == '5')
					{
						printf("Free space in local disks...\n");

						char temp[1024];
						char answer5[1024] = "";
						char *name_disk[] = { "C:", "D:", "E:", "F:", "G:", "H:", "I:", "J:", "K:", "L:",
							"M:", "N:", "O:", "P:", "Q:", "R:", "S:", "T:", "U:", " V:",
							"W:", "X:", "Y:", "Z:" };
						_int64 TotalNumberOfFreeBytes;
						strcpy(answer5, "Disks:\n");
						int flag;
						
						for (int i = 0; i < 24; i++)
						{
							wchar_t* wString = new wchar_t[4096];
							MultiByteToWideChar(CP_ACP, 0, name_disk[i], -1, wString, 4096);
							
							flag = GetDriveType(wString);

							if (flag == 3)
							{
								strcat(answer5, name_disk[i]);
								strcat(answer5, " - FIXED\n");

								TotalNumberOfFreeBytes = 0;
								GetDiskFreeSpaceEx(wString,
									(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);

								_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);

								strcat(answer5, "Free ");
								strcat(answer5, temp);
								strcat(answer5, " Gb\n");
							}
							else if (flag == 2)
							{
								strcat(answer5, name_disk[i]);
								strcat(answer5, " - REMOVABLE\n");

								TotalNumberOfFreeBytes = 0;
								GetDiskFreeSpaceEx(wString,
									(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);
								_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);

								strcat(answer5, "Free ");
								strcat(answer5, temp);
								strcat(answer5, " Gb\n");
							}
							else if (flag == 4)
							{
								strcat(answer5, name_disk[i]);
								strcat(answer5, " - REMOTE\n");

								TotalNumberOfFreeBytes = 0;
								GetDiskFreeSpaceEx(wString,
									(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);
								
								_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);
								
								strcat(answer5, "Free ");
								strcat(answer5, temp);
								strcat(answer5, " Gb\n");
							}
							else if (flag == 6)
							{
								strcat(answer5, name_disk[i]);
								strcat(answer5, " - RAMDISK\n");
								
								TotalNumberOfFreeBytes = 0;
								GetDiskFreeSpaceEx(wString,
									(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);
								
								_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);
								
								strcat(answer5, "Free ");
								strcat(answer5, temp);
								strcat(answer5, " Gb\n");
							}
							else if (flag == 5)
							{
								strcat(answer5, name_disk[i]);
								strcat(answer5, " - CDROM\n");
								
								TotalNumberOfFreeBytes = 0;
								GetDiskFreeSpaceEx(wString,
									(PULARGE_INTEGER)&TotalNumberOfFreeBytes, NULL, NULL);
								
								_itoa(TotalNumberOfFreeBytes / 1024 / 1024 / 1024, temp, 10);
								
								strcat(answer5, "Free ");
								strcat(answer5, temp);
								strcat(answer5, " Gb\n");
							}
						}
						
						DWORD count = strlen(answer5) + 1;
						if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)answer5, &count, count))
						{
							printf("Encrypt: ERROR!\n");
						}
						//send(g_ctxs[key].socket, answer5, count, 0);
						
						help_for_write(key, answer5, count);

						ZeroMemory(&answer5, sizeof(answer5));
						
						buffer = '0';
						schedule_read(key);
					}
					else if (buffer == '6')
					{
						printf("Get Access rights...\n");

						char domain[256];
						char user[256];
						
						ACL_SIZE_INFORMATION acl_size;
						ACCESS_ALLOWED_ACE * pACE;
						PACL dacl;
						PSID pOwnerSID;
						
						char type;
						char buf;
						char path[128] = { 0 };
						char out_buf[8192];
						ZeroMemory(&out_buf, sizeof(out_buf));
						
						LPSTR SID_string;
						
						if (recv(g_ctxs[key].socket, &buf, sizeof(buf), 0) == 0) // f d k receive
						{
							strcat(out_buf, "GET_TYPE_OBJECT: ERROR!\n");

							printf("GET_TYPE_OBJECT: ERROR!\n");
						}
						else
						{
							if (buf == 'f') type = SE_FILE_OBJECT;
							if (buf == 'd') type = SE_FILE_OBJECT;
							if (buf == 'k') type = SE_REGISTRY_KEY;
						}
						if (recv(g_ctxs[key].socket, (char *)&path, sizeof(path), 0) == 0) //Get path
						{
							strcat(out_buf, "GET_PATH_OBJECT: ERROR!\n");
							
							printf("GET_PATH_OBJECT: ERROR!\n");
						}
						if (GetNamedSecurityInfoA(path, (SE_OBJECT_TYPE)type, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &pOwnerSID) != ERROR_SUCCESS) {
							strcat(out_buf, "ACCESS ERROR!\n");
							
							printf("ACCESS ERROR!\n");
						}
						else
						{
							memset(out_buf, 0, 8192);
							
							GetAclInformation(dacl, &acl_size, sizeof(acl_size), AclSizeInformation);
							
							for (int i = 0; i < acl_size.AceCount; i++)
							{
								memset(domain, 0, 256);
								memset(user, 0, 256);
							
								DWORD userlen = sizeof(user);
								DWORD domlen = sizeof(domain);
								
								SID_NAME_USE sid_name;
								PSID pSID;
								LPSTR strSid = 0;
								
								GetAce(dacl, i, (PVOID *)&pACE);
								pSID = (PSID)(&(pACE->SidStart));
								
								SECURITY_INFORMATION si = GROUP_SECURITY_INFORMATION &
									LABEL_SECURITY_INFORMATION &
									DACL_SECURITY_INFORMATION &
									LABEL_SECURITY_INFORMATION &
									OWNER_SECURITY_INFORMATION;
								
								if (LookupAccountSidA(NULL, pSID, user, &userlen, domain, &domlen, &sid_name))
								{
									strcat(out_buf, "\nAccount: ");
									strcat(out_buf, domain);
									strcat(out_buf, "\\");
									strcat(out_buf, user);
									strcat(out_buf, " \n");
									strcat(out_buf, "Account's SID: ");
									ConvertSidToStringSidA(pSID, &SID_string);
									strcat(out_buf, SID_string);
									strcat(out_buf, " \n");
									strcat(out_buf, "ACE type: ");
								
									switch (pACE->Header.AceType)
									{
									case ACCESS_DENIED_ACE_TYPE:
										strcat(out_buf, "ACCESS: Denied\n");
										break;
									case ACCESS_ALLOWED_ACE_TYPE:
										strcat(out_buf, "ACCESS: Allowed\n");
										break;
									default:
										strcat(out_buf, "Audit\n");
									}
									
									/*strcat(out_buf, "Access mask: ");
									for (j = 0; j < 32; j++)
									out_buf[strlen(out_buf)] = '0' + pACE->Mask / (1 << (31 - j)) % 2;*/
									
									strcat(out_buf, "Generic rights: \n");
									
									// https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/access-mask

									//generic rights

									//You can also specify the folowing generic access rights. these also apply to all types of executive objects.

									if ((pACE->Mask & 1)) { strcat(out_buf, "GENERIC_READ\n"); } //the caller can perform normal read operations on the object
									if ((pACE->Mask & 2)) { strcat(out_buf, "GENERIC_WRITE\n"); } //the caller can perform normal write operations on the object
									if ((pACE->Mask & 4)) { strcat(out_buf, "GENERIC_EXECUTE\n"); } //the caller can execute the object
									
									//standart rights
									strcat(out_buf, "Standard rights: \n");
									if ((pACE->Mask & SYNCHRONIZE)) { strcat(out_buf, "SYNCHRONIZE\n"); } //the caller can perform a wait operation on the object
									if ((pACE->Mask & WRITE_OWNER)) { strcat(out_buf, "WRITE_OWNER\n"); } //the caller can change the ownership information for the file 
									if ((pACE->Mask & WRITE_DAC)) { strcat(out_buf, "WRITE_DAC\n"); } //the caller can change the DACL
									if ((pACE->Mask & READ_CONTROL)) { strcat(out_buf, "READ_CONTROL\n"); } //caller can read the ACL
									if ((pACE->Mask & DELETE)) { strcat(out_buf, "DELETE\n"); } //the caller can delete the object 
									
									if (type == SE_FILE_OBJECT)
									{
										if (buf == 'f')
										{
											strcat(out_buf, "Specific rights for file:\n");
									
											if ((pACE->Mask & FILE_READ_DATA)) { strcat(out_buf, "FILE_READ_DATA\n"); }
											if ((pACE->Mask & FILE_WRITE_DATA)) { strcat(out_buf, "FILE_WRITE_DATA\n"); }
											if ((pACE->Mask & FILE_APPEND_DATA)) { strcat(out_buf, "FILE_APPEND_DATA\n"); }
											if ((pACE->Mask & FILE_READ_EA)) { strcat(out_buf, "FILE_READ_EA\n"); }
											if ((pACE->Mask & FILE_WRITE_EA)) { strcat(out_buf, "FILE_WRITE_EA\n"); }
											if ((pACE->Mask & FILE_EXECUTE)) { strcat(out_buf, "FILE_EXECUTE\n"); }
											if ((pACE->Mask & FILE_READ_ATTRIBUTES)) { strcat(out_buf, "FILE_READ_ATTRIBUTES\n"); }
											if ((pACE->Mask & FILE_WRITE_ATTRIBUTES)) { strcat(out_buf, "FILE_WRITE_ATTRIBUTES\n"); }
										}
										if (buf == 'd')
										{
											strcat(out_buf, "Specific rights for directory:\n");
											
											if ((pACE->Mask & FILE_LIST_DIRECTORY)) { strcat(out_buf, "FILE_LIST_DIRECTORY\n"); }
											if ((pACE->Mask & FILE_ADD_FILE)) { strcat(out_buf, "FILE_ADD_FILE\n"); }
											if ((pACE->Mask & FILE_ADD_SUBDIRECTORY)) { strcat(out_buf, "FILE_ADD_SUBDIRECTORY\n"); }
											if ((pACE->Mask & FILE_READ_EA)) { strcat(out_buf, "FILE_READ_EA\n"); }
											if ((pACE->Mask & FILE_WRITE_EA)) { strcat(out_buf, "FILE_WRITE_EA\n"); }
											if ((pACE->Mask & FILE_TRAVERSE)) { strcat(out_buf, "FILE_TRAVERSE\n"); }
											if ((pACE->Mask & FILE_DELETE_CHILD)) { strcat(out_buf, "FILE_DELETE_CHILD\n"); }
											if ((pACE->Mask & FILE_READ_ATTRIBUTES)) { strcat(out_buf, "FILE_READ_ATTRIBUTES\n"); }
											if ((pACE->Mask & FILE_WRITE_ATTRIBUTES)) { strcat(out_buf, "FILE_WRITE_ATTRIBUTES\n"); }
										}
									}

									// https://msdn.microsoft.com/ru-ru/library/windows/desktop/ms724878(v=vs.85).aspx
									if (type == SE_REGISTRY_KEY)
									{
										strcat(out_buf, "Registry key rights:\n ");
										
										if ((pACE->Mask & KEY_CREATE_SUB_KEY)) // Required to create a subkey of a registry key.
										{
											strcat(out_buf, "KEY_CREATE_SUB_KEY\n ");
										}
										if (pACE->Mask & KEY_ENUMERATE_SUB_KEYS) //Required to enumerate the subkeys of a registry key.
										{
											strcat(out_buf, "KEY_ENUMERATE_SUB_KEYS\n ");
										}
										if (pACE->Mask & KEY_NOTIFY) //Required to request change notifications for a registry key or for subkeys of a registry key.
										{
											strcat(out_buf, "KEY_NOTIFY\n ");
										}
										if (pACE->Mask & KEY_QUERY_VALUE) //Required to query the values of a registry key.
										{
											strcat(out_buf, "KEY_QUERY_VALUE\n ");
										}
										if (pACE->Mask & KEY_SET_VALUE) //Required to create, delete, or set a registry value.
										{
											strcat(out_buf, "KEY_SET_VALUE\n ");
										}
									}
								}
							}
						}

						DWORD count = strlen(out_buf) + 1;
						if (!CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)out_buf, &count, count))
						{
							printf("Encrypt: ERROR!\n");
						}
						//send(g_ctxs[key].socket, out_buf, count, 0);
						
						help_for_write(key, out_buf, count);

						buffer = '0';
						count = 0;
						schedule_read(key);
					}
					else if (buffer == '7')
					{
						printf("Get file owner...\n");

						char stack[1024];
						ZeroMemory(&stack, sizeof(stack));
						
						DWORD dwRes = 0;
						PSID pOwnerSID;
						
						char path[128] = { 0 };
						char buf = { 0 };
						char sid[1024] = { 0 };
						
						PSECURITY_DESCRIPTOR pSecDescr;
						
						recv(g_ctxs[key].socket, &buf, sizeof(buf), 0);
						recv(g_ctxs[key].socket, (char *)&path, sizeof(path), 0);
						
						//wchar_t* wString = new wchar_t[4096];
						//MultiByteToWideChar(CP_ACP, 0, path, -1, wString, 4096);
						
						if (buf == 'f')
						{// по пути к папке или файлу извклекаем его SID
							dwRes = GetNamedSecurityInfoA(path, SE_FILE_OBJECT,
								OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
						}
						else
						{
							dwRes = GetNamedSecurityInfoA(path, SE_REGISTRY_KEY,
								OWNER_SECURITY_INFORMATION, &pOwnerSID, NULL, NULL, NULL, &pSecDescr);
						}

						//HANDLE hFile = CreateFileA(path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
						
						if (dwRes != ERROR_SUCCESS)
						{
							printf("Can't to take owner's SID %i\n", GetLastError());//error
							LocalFree(pSecDescr);
						}
						
						char szOwnerName[256] = { 0 };
						char szDomainName[256] = { 0 };
						
						DWORD dwUserNameLength = sizeof(szOwnerName);
						DWORD dwDomainNameLength = sizeof(szDomainName);
						SID_NAME_USE sidUse;
						
						/*Функция LookupAccountSid принимает идентификатор безопасности (SID) в качестве входных данных. Он извлекает имя учетной записи для этого SID и имя первого домена, на котором этот идентификатор найден.*/
						dwRes = LookupAccountSidA(NULL, pOwnerSID, szOwnerName, &dwUserNameLength,
							szDomainName, &dwDomainNameLength, &sidUse);
						
						if (dwRes == 0)
						{
							printf("ERROR!\n");
							//error
						}
						else
						{
							//printf("Owner name = %s\t Domain = %s\n", szOwnerName, szDomainName);

							strcat(stack, "Owner name: ");
							strcat(stack, szOwnerName);
							strcat(stack, "\n");
							strcat(stack, "Domain: ");
							strcat(stack, szDomainName);
							strcat(stack, "\n");
							
							LPWSTR SID = NULL;
							
							char name[1024];
							ZeroMemory(&name, sizeof(name));

							BOOL flag = ConvertSidToStringSid(pOwnerSID, &SID);
							
							WideCharToMultiByte(CP_ACP, 0, SID, -1, name, sizeof(name), 0, 0);
							
							strcpy(sid, name);
							strcat(stack, "SID: ");
							strcat(stack, sid);
							strcat(stack, "\n");
							
							DWORD count = strlen(stack) + 1;
							CryptEncrypt(g_ctxs[key].hSessionKey, 0, true, 0, (BYTE *)stack, &count, count);
							//send(g_ctxs[key].socket, stack, count, 0); // HKEY_CURRENT_USER\Control Panel\Colors
							help_for_write(key, stack, count);
						}

						buffer = '0';
						schedule_read(key);
					}
					else if (buffer == '8')
					{

						printf("Client close the connection\n");

						//closesocket(my_sock);
						// Данные отправлены полностью, прервать все оммуникации,
						// добавить в порт событие на завершение работы
						CancelIo((HANDLE)g_ctxs[key].socket);
						PostQueuedCompletionStatus(g_io_port, 0, key,
							&g_ctxs[key].overlap_cancel);


						//printf("Отключился клиент...\n");
						
						closesocket(g_ctxs[key].socket);
						
						count_client--;
						
						//printf("Клиентов: %d\n", count_client);

						schedule_read(key);
						
						break;
					}
					else if (buffer == '0')
					{
						return;
					}

				}
			}
		}
	}
}

int main()
{
	setlocale(LC_ALL, "Russian");

	io_serv();

	return 0;
}
