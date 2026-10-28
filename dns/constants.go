package dns

type Type uint16

const (
	TypeA     Type = 1
	TypeNS    Type = 2
	TypeCNAME Type = 5
	TypeSOA   Type = 6
	TypePTR   Type = 12
	TypeMX    Type = 15
	TypeTXT   Type = 16
	TypeAAAA  Type = 28
)

/*
TypeA     (1)  - IPv4-адрес хоста (4 байта).
TypeNS    (2)  - Доменное имя авторитетного сервера для зоны.
TypeCNAME (5)  - Каноническое имя (псевдоним другого домена).
TypeSOA   (6)  - Параметры зоны (главный сервер, email админа, серийный номер, TTL).
TypePTR   (12) - Обратный DNS (поиск доменного имени по IP-адресу).
TypeMX    (15) - Почтовый шлюз домена и его приоритет.
TypeTXT   (16) - Произвольный текст.
TypeAAAA  (28) - IPv6-адрес хоста (16 байт).
*/

type Class uint16

const (
	ClassINET Class = 1
)

type RCode uint8

const (
	RCodeNoError        RCode = 0
	RCodeFormatError    RCode = 1
	RCodeServerFailure  RCode = 2
	RCodeNameError      RCode = 3
	RCodeNotImplemented RCode = 4
	RCodeRefused        RCode = 5
)

/*
RCodeNoError        (0) - Успех. Ошибок нет, записи найдены (или пустой ответ).
RCodeFormatError    (1) - Сервер не смог распарсить входящий запрос.
RCodeServerFailure  (2) - ServFail. Внутренний сбой сервера .
RCodeNameError      (3) - NXDomain. Запрашиваемое доменное имя не существует.
RCodeNotImplemented (4) - Тип запроса (Opcode) не поддерживается этим сервером.
RCodeRefused        (5) - Сервер отказывается отвечать (например, закрыт рекурсивный доступ).
*/
