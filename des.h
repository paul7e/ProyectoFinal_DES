#ifndef DES_H
#define DES_H

#include <stdint.h>
#include <stdio.h>

#define DES_RONDAS 16

typedef struct {
    uint64_t subclave[DES_RONDAS];
} des_clave_expandida;

typedef enum {
    DES_CIFRAR,
    DES_DESCIFRAR
} des_sentido;

void des_expandir_clave(uint64_t clave, des_clave_expandida *expandida);

uint64_t des_cifrar(uint64_t texto_plano, const des_clave_expandida *expandida);

uint64_t des_descifrar(uint64_t texto_cifrado, const des_clave_expandida *expandida);

uint64_t des_procesar_bloque(uint64_t bloque,
                             const des_clave_expandida *expandida,
                             des_sentido sentido,
                             FILE *traza);

void des_imprimir_subclaves(const des_clave_expandida *expandida, FILE *salida);

int des_paridad_correcta(uint64_t clave);

uint64_t des_ajustar_paridad(uint64_t clave);

typedef struct {
    des_clave_expandida k1, k2, k3;
} tdea_claves;

void tdea_expandir_claves(uint64_t k1, uint64_t k2, uint64_t k3, tdea_claves *claves);

uint64_t tdea_cifrar(uint64_t texto_plano, const tdea_claves *claves);

uint64_t tdea_descifrar(uint64_t texto_cifrado, const tdea_claves *claves);

uint64_t des_bytes_a_bloque(const uint8_t bytes[8]);

void des_bloque_a_bytes(uint64_t bloque, uint8_t bytes[8]);

#endif
