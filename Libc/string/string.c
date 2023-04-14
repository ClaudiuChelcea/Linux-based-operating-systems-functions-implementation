#include <string.h>

typedef enum {
    false = 0,
    true = 1
};

typedef short bool;

#define DIE_NULL(condition, msg) do {                                       \
    if (condition) {                                                        \
        return NULL;                                                        \
    }                                                                       \
} while(0);

#define DIE_VOID(condition, msg) do {                                       \
    if (condition) {                                                        \
        return;                                                             \
    }                                                                       \
} while(0);

#define DIE_INT(condition, msg) do {                                        \
    if (condition) {                                                        \
        return -1;                                                          \
    }                                                                       \
} while(0);

char *strcpy(char *destination, const char *source)
{
    DIE_NULL(destination == NULL, "STRCPY");
    DIE_NULL(source == NULL, "STRCPY");

    int i = 0;
	for(;source[i] != '\0';++i)
		destination[i] = source[i];

	destination[i] = '\0';

	return destination;
}

char *strncpy(char *destination, const char *source, size_t len)
{
    DIE_NULL(destination == NULL, "STRNCPY");
    DIE_NULL(source == NULL, "STRNCPY");

	int i = 0;
	for(;source[i] != '\0' && i < len;++i)
		destination[i] = source[i];

	for(;i < len; ++i)
		destination[i] = '\0';

	return destination;
}

char *strcat(char *destination, const char *source)
{
    DIE_NULL(destination == NULL, "STRCAT");
    DIE_NULL(source == NULL, "STRCAT");

    strcpy(&destination[strlen(destination)], source);
	return destination;
}

char *strncat(char *destination, const char *source, size_t len)
{
    DIE_NULL(destination == NULL, "STRNCAT");
    DIE_NULL(source == NULL, "STRNCAT");

    int i = 0;
	int len_Dest = strlen(destination);

	while (source[i] && i < len)
	{
		destination[len_Dest + i] = source[i];
		i++;
	}

	destination[len_Dest + i] = '\0';

	return (destination);
}

int strcmp(const char *str1, const char *str2)
{
    DIE_INT(str1 == NULL, "STRCMP");
    DIE_INT(str2 == NULL, "STRCMP");

    unsigned int i = 0;

	for(;str1[i] != '\0' && str2[i] != '\0' && str1[i] == str2[i];++i);

	return str1[i] - str2[i];
}

int strncmp(const char *str1, const char *str2, size_t len)
{
    DIE_INT(str1 == NULL, "STRNCMP");
    DIE_INT(str2 == NULL, "STRNCMP");

    int i = 0;
	unsigned char *t1 = (unsigned char *)str1;
	unsigned char *t2 = (unsigned char *)str2;

	for(;!(t1[i] == '\0' && t2[i] == '\0') && len > 0;++i) {
		if (t1[i] != t2[i])
			return (t1[i] - t2[i]);
		len--;
	}

	return 0;
}

size_t strlen(const char *str) {

    char *ptr = str;
    while (*ptr != NULL) {
		ptr = ptr + 1; // + 1 char
    }

    return (int) (ptr - str);
}

char *strchr(const char *str, int c)
{
    DIE_NULL(str == NULL, "STRCHR");

    int i = 0;

	for(;(str && str[i]) && (char)c != str[i];++i);

	if (c == str[i])
		return ((char *)str + i);
	
    return NULL;
}

char *strrchr(const char *str, int c)
{
    DIE_NULL(str == NULL, "STRRCHR");

    int i = strlen(str);
	
	bool pass = 0;
	for(int i = strlen(str); i >= 0; i--) {
		if (c == str[i]) {
			pass = -1;
			return ((char *)str + i);
		}
	}
	
	if(pass == 0) {
		return NULL;
	} else {
		// Can't happen
	}		
}

char *strstr(const char *haystack, const char *needle)
{
    DIE_NULL(haystack == NULL, "STRSTR");
    DIE_NULL(needle == NULL, "STRSTR");

    int size = 0;

	if (*needle == '\0') {
		return ((char *) haystack);
	} else {
		
		size = strlen(needle);
	
		while (*haystack)
		{
			if (strncmp(haystack++, needle, size) == 0)
				return ((char *)--haystack);
		}
		
		return NULL;
	}

	return NULL;
}

static inline char *strrstr_reverse_X(const char *haystack, const char *needle) {
    int haystack_len = strlen(haystack);
    int needle_len = strlen(needle);

    if (needle_len > haystack_len) {
        return NULL;
    } else {
		for (int i = haystack_len - 1; i >= needle_len - 1; i--) {
			if (strncmp(haystack + i - needle_len + 1, needle, needle_len) == 0) {
				return (char *)(haystack + i - needle_len + 1);
			}
		}
	}

    return NULL;
}

// Check if string is nor NULL nor empty
bool is_valid_string(const char *str) {
    return str != NULL && strlen(str) > 0;
}

char *strrstr(const char *haystack, const char *needle) {
    
	char *default_retval = NULL;

    if (!is_valid_string(haystack) || !is_valid_string(needle)) {
        return default_retval;
    }

    int haystack_len = strlen(haystack);
    int needle_len = strlen(needle);

    if (needle_len > haystack_len) {
        return default_retval;
    }

    int i = haystack_len - needle_len;
    while (i > 0) {
        if (strncmp(haystack + i, needle, needle_len) == 0) {
            return (char *)(haystack + i);
        }
        i--;
    }

    return (strncmp(haystack, needle, needle_len) == 0) ? (char*) haystack : default_retval;
}

void *memcpy(void *destination, const void *source, size_t num)
{
    DIE_NULL(destination == NULL, "MEMCPY");
    DIE_NULL(source == NULL, "MEMCPY");

    unsigned int i = 0;
	unsigned char *a = (unsigned char *)destination;
	unsigned char *b = (unsigned char *)source;

	for (;i < num; i++) {
		((unsigned char *) destination)[i] = ((unsigned char *) source)[i];
	}

    return destination;
}

void *memmove(void *destination, const void *source, size_t num)
{
    DIE_NULL(destination == NULL, "MEMMOVE");
    DIE_NULL(source == NULL, "MEMMOVE");

    char *strsrc = (char*)source;
	char *strdst = (char*)destination;

    if (strsrc < strdst)
	{
		strsrc = strsrc + num - 1;
		strdst = strdst + num - 1;
		while (num > 0)
		{
			*strdst-- = *strsrc--;
			num--;
		}
	} else {
		while (num > 0)
		{
			*strdst++ = *strsrc++;
			num--;
		}
	}
	
    return destination;
}

int memcmp(const void *ptr1, const void *ptr2, size_t num)
{
    DIE_INT(ptr1 == NULL, "MEMCMP");
    DIE_INT(ptr2 == NULL, "MEMCMP");

    unsigned char *str1 = (unsigned char*)ptr1;
	unsigned char *str2 = (unsigned char*)ptr2;

    while (num > 0 && *str1 == *str2)
	{
		str1++;
		str2++;
		num--;
	}
	
    if (num == 0) {
		return (0);
    } else {
		return (*str1 - *str2);
    }
}

void *memset(void *source, int value, size_t num)
{
    DIE_NULL(source == NULL, "MEMSET");

    unsigned char *tmp_str = NULL;

	if (num == 0) {
		return (source);
    } else {
		tmp_str = (unsigned char *)source;
	
		while (num--)
		{
			*tmp_str = (unsigned char)value;
			if (num != 0)
				tmp_str++;
		}

		return (source);
	}

	return NULL;
}