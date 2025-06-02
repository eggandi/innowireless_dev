
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


const char *filename = "empty_crl.oer";
const char *file_contents = "";

int Dot2Test_ConvertHexStrToOctets(const char *hex_str, uint8_t *octs)
{
  int i, octs_size = strlen(hex_str) / 2;
  char t[3];

  for (i = 0; i < octs_size; i++){
    memcpy(t, (hex_str + i*2), 2);
    t[2] = '\0';
    *(octs + i) = (uint8_t)strtoul(t, NULL, 16);
  }
  return octs_size;
}

int main()
{
  uint8_t octs[8000];
  int octs_size = Dot2Test_ConvertHexStrToOctets(file_contents, octs);

  FILE *fp = fopen(filename, "w");
  if (fp) {
    fwrite(octs, 1, octs_size, fp);
    fclose(fp);
  }
  return 0;
}

