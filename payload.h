unsigned char a10_a11rxw[] = {
    0xe5, 0x03, 0x1e, 0xaa, 0x00, 0x01, 0xc0, 0xd2, 0x19, 0x00, 0x00, 0x94,
    0x00, 0x00, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4, 0x1f, 0x75, 0x08, 0xd5,
    0x04, 0x10, 0x38, 0xd5, 0x00, 0x00, 0x80, 0xd2, 0x00, 0x10, 0x18, 0xd5,
    0x60, 0x03, 0x00, 0x58, 0x00, 0x00, 0x40, 0xf9, 0x00, 0xf4, 0x49, 0x92,
    0x01, 0x03, 0x00, 0x58, 0x20, 0x00, 0x00, 0xf9, 0xe0, 0x03, 0x04, 0xaa,
    0x00, 0xf8, 0x6c, 0x92, 0x00, 0x10, 0x18, 0xd5, 0x9f, 0x3f, 0x03, 0xd5,
    0x1f, 0x87, 0x08, 0xd5, 0x9f, 0x3f, 0x03, 0xd5, 0xdf, 0x3f, 0x03, 0xd5,
    0x00, 0x40, 0x38, 0xd5, 0x00, 0xf4, 0x7c, 0x92, 0x00, 0x40, 0x18, 0xd5,
    0xe0, 0x03, 0x05, 0xaa, 0x20, 0x40, 0x18, 0xd5, 0xe0, 0x03, 0x9f, 0xd6,
    0x01, 0x01, 0xa0, 0xd2, 0x02, 0x00, 0x80, 0xd2, 0x3f, 0x00, 0x02, 0xeb,
    0xa0, 0x00, 0x00, 0x54, 0x20, 0x7e, 0x0b, 0xd5, 0x00, 0x00, 0x01, 0x91,
    0x42, 0x00, 0x01, 0x91, 0xfb, 0xff, 0xff, 0x17, 0xc0, 0x03, 0x5f, 0xd6,
    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 // SDRAM_PAGE1: 0x180002000
};
unsigned int a10_a11rxw_len = 152;

unsigned char go_cmd_hook[] = {
    0xd0, 0x01, 0x00, 0x58, 0x10, 0x02, 0x40, 0xf9, 0x1f, 0x02, 0x1f, 0xeb,
    0x01, 0x01, 0x00, 0x54, 0x90, 0x01, 0x00, 0x58, 0x10, 0x02, 0x40, 0xf9,
    0x1f, 0x02, 0x1f, 0xeb, 0x41, 0x00, 0x00, 0x54, 0xc0, 0x03, 0x5f, 0xd6,
    0xf0, 0x00, 0x00, 0x58, 0x00, 0x02, 0x1f, 0xd6, 0x70, 0x00, 0x00, 0x58,
    0x00, 0x02, 0x1f, 0xd6, 0x00, 0x00, 0x00, 0x00,
    0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
    0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43, 0x43
};
unsigned int go_cmd_hook_len = 72;

unsigned char tram[] = {
    0x50, 0x00, 0x00, 0x58,
    0x00, 0x02, 0x1f, 0xd6,
    0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44
};
unsigned int tram_len = 16;
