#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "des.h"

static int leer_hex64(const char *texto, uint64_t *resultado)
{
    if (strlen(texto) != 16) {
        return 0;
    }

    uint64_t valor = 0;
    for (int i = 0; i < 16; i++) {
        char c = (char)toupper((unsigned char)texto[i]);
        int digito;

        if (c >= '0' && c <= '9')      digito = c - '0';
        else if (c >= 'A' && c <= 'F') digito = c - 'A' + 10;
        else                           return 0;

        valor = (valor << 4) | (uint64_t)digito;
    }
    *resultado = valor;
    return 1;
}

static void leer_argumentos_hex(char **argv, int cantidad, uint64_t *destino)
{
    for (int i = 0; i < cantidad; i++) {
        if (!leer_hex64(argv[i], &destino[i])) {
            fprintf(stderr, "Error: \"%s\" no son 16 dígitos hexadecimales.\n", argv[i]);
            exit(EXIT_FAILURE);
        }
    }
}

static void avisar_si_paridad_incorrecta(uint64_t clave)
{
    if (!des_paridad_correcta(clave)) {
        fprintf(stderr,
                "Aviso: la clave %016llX no tiene paridad impar en todos sus bytes.\n"
                "       Se usa igual (el algoritmo ignora esos bits); con paridad\n"
                "       corregida sería %016llX.\n",
                (unsigned long long)clave,
                (unsigned long long)des_ajustar_paridad(clave));
    }
}

typedef struct {
    const char *descripcion;
    uint64_t clave;
    uint64_t texto_plano;
    uint64_t texto_cifrado;
} vector_des;

typedef struct {
    const char *descripcion;
    uint64_t k1, k2, k3;
    uint64_t texto_plano;
    uint64_t texto_cifrado;
} vector_tdea;

static const vector_des VECTORES_DES[] = {
    { "Ejemplo clásico resuelto a mano",
      0x133457799BBCDFF1ULL, 0x0123456789ABCDEFULL, 0x85E813540F0AB405ULL },
    { "Texto cifrado todo ceros",
      0x0E329232EA6D0D73ULL, 0x8787878787878787ULL, 0x0000000000000000ULL },
    { "\"Now is t\" (ASCII)",
      0x0123456789ABCDEFULL, 0x4E6F772069732074ULL, 0x3FA40E8A984D4815ULL },
    { "NIST SP 800-17, texto variable #1",
      0x0101010101010101ULL, 0x8000000000000000ULL, 0x95F8A5E5DD31D900ULL },
    { "NIST SP 800-17, clave variable #1",
      0x8001010101010101ULL, 0x0000000000000000ULL, 0x95A8D72813DAA94DULL },
};

static const vector_tdea VECTORES_TDEA[] = {
    { "NIST SP 800-67, claves independientes (Opción 1)",
      0x0123456789ABCDEFULL, 0x23456789ABCDEF01ULL, 0x456789ABCDEF0123ULL,
      0x5468652071756663ULL, 0xA826FD8CE53B855FULL },
    { "Opción 3 (K1=K2=K3) equivale a DES simple",
      0x133457799BBCDFF1ULL, 0x133457799BBCDFF1ULL, 0x133457799BBCDFF1ULL,
      0x0123456789ABCDEFULL, 0x85E813540F0AB405ULL },
};

#define CANTIDAD(arreglo) (sizeof(arreglo) / sizeof((arreglo)[0]))

static int ejecutar_pruebas(void)
{
    int fallos = 0;

    printf("Pruebas de DES\n");
    for (size_t i = 0; i < CANTIDAD(VECTORES_DES); i++) {
        const vector_des *v = &VECTORES_DES[i];
        des_clave_expandida ke;
        des_expandir_clave(v->clave, &ke);

        uint64_t cifrado   = des_cifrar(v->texto_plano, &ke);
        uint64_t descifrado = des_descifrar(cifrado, &ke);
        int ok = (cifrado == v->texto_cifrado) && (descifrado == v->texto_plano);

        printf("  [%s] %s\n", ok ? " OK " : "FALLA", v->descripcion);
        if (!ok) {
            printf("         esperado %016llX, obtenido %016llX\n",
                   (unsigned long long)v->texto_cifrado, (unsigned long long)cifrado);
            fallos++;
        }
    }

    printf("\nPruebas de Triple DES\n");
    for (size_t i = 0; i < CANTIDAD(VECTORES_TDEA); i++) {
        const vector_tdea *v = &VECTORES_TDEA[i];
        tdea_claves claves;
        tdea_expandir_claves(v->k1, v->k2, v->k3, &claves);

        uint64_t cifrado    = tdea_cifrar(v->texto_plano, &claves);
        uint64_t descifrado = tdea_descifrar(cifrado, &claves);
        int ok = (cifrado == v->texto_cifrado) && (descifrado == v->texto_plano);

        printf("  [%s] %s\n", ok ? " OK " : "FALLA", v->descripcion);
        if (!ok) {
            printf("         esperado %016llX, obtenido %016llX\n",
                   (unsigned long long)v->texto_cifrado, (unsigned long long)cifrado);
            fallos++;
        }
    }

    printf("\nPropiedades\n");
    {
        uint64_t k = 0x133457799BBCDFF1ULL, p = 0x0123456789ABCDEFULL;
        des_clave_expandida ke, ke_neg;
        des_expandir_clave(k, &ke);
        des_expandir_clave(~k, &ke_neg);
        int ok = des_cifrar(~p, &ke_neg) == ~des_cifrar(p, &ke);
        printf("  [%s] Propiedad del complemento\n", ok ? " OK " : "FALLA");
        if (!ok) fallos++;
    }
    {
        int ok = des_paridad_correcta(0x133457799BBCDFF1ULL)
              && !des_paridad_correcta(0x0000000000000000ULL)
              && des_ajustar_paridad(0x0000000000000000ULL) == 0x0101010101010101ULL;
        printf("  [%s] Comprobación y ajuste de paridad\n", ok ? " OK " : "FALLA");
        if (!ok) fallos++;
    }

    printf("\n%s\n", fallos == 0 ? "Todas las pruebas pasaron."
                                 : "HAY PRUEBAS QUE FALLARON.");
    return fallos == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static int mostrar_traza(uint64_t clave, uint64_t bloque)
{
    des_clave_expandida ke;
    des_expandir_clave(clave, &ke);

    printf("Clave: %016llX\n\n", (unsigned long long)clave);
    printf("Subclaves generadas por KS (PC-1, rotaciones, PC-2):\n");
    des_imprimir_subclaves(&ke, stdout);
    printf("\n");

    uint64_t cifrado = des_procesar_bloque(bloque, &ke, DES_CIFRAR, stdout);
    uint64_t vuelta  = des_descifrar(cifrado, &ke);

    printf("\nComprobación: al descifrar %016llX se obtiene %016llX (%s)\n",
           (unsigned long long)cifrado, (unsigned long long)vuelta,
           vuelta == bloque ? "coincide con el original" : "¡NO coincide!");
    return EXIT_SUCCESS;
}

static void mostrar_uso(const char *programa)
{
    fprintf(stderr,
        "Uso:\n"
        "  %s pruebas\n"
        "  %s traza [CLAVE BLOQUE]\n"
        "  %s cifrar     CLAVE BLOQUE\n"
        "  %s descifrar  CLAVE BLOQUE\n"
        "  %s tdea-cifrar    K1 K2 K3 BLOQUE\n"
        "  %s tdea-descifrar K1 K2 K3 BLOQUE\n"
        "Claves y bloques: 16 dígitos hexadecimales (ej. 133457799BBCDFF1).\n",
        programa, programa, programa, programa, programa, programa);
}

int main(int argc, char **argv)
{
    if (argc < 2 || strcmp(argv[1], "pruebas") == 0) {
        return ejecutar_pruebas();
    }

    const char *orden = argv[1];

    if (strcmp(orden, "traza") == 0) {
        uint64_t valores[2] = { 0x133457799BBCDFF1ULL, 0x0123456789ABCDEFULL };
        if (argc == 4) {
            leer_argumentos_hex(&argv[2], 2, valores);
        } else if (argc != 2) {
            mostrar_uso(argv[0]);
            return EXIT_FAILURE;
        }
        return mostrar_traza(valores[0], valores[1]);
    }

    if ((strcmp(orden, "cifrar") == 0 || strcmp(orden, "descifrar") == 0) && argc == 4) {
        uint64_t valores[2];
        leer_argumentos_hex(&argv[2], 2, valores);
        avisar_si_paridad_incorrecta(valores[0]);

        des_clave_expandida ke;
        des_expandir_clave(valores[0], &ke);
        uint64_t resultado = (orden[0] == 'c') ? des_cifrar(valores[1], &ke)
                                               : des_descifrar(valores[1], &ke);
        printf("%016llX\n", (unsigned long long)resultado);
        return EXIT_SUCCESS;
    }

    if ((strcmp(orden, "tdea-cifrar") == 0 || strcmp(orden, "tdea-descifrar") == 0)
        && argc == 6) {
        uint64_t valores[4];
        leer_argumentos_hex(&argv[2], 4, valores);
        for (int i = 0; i < 3; i++) {
            avisar_si_paridad_incorrecta(valores[i]);
        }

        tdea_claves claves;
        tdea_expandir_claves(valores[0], valores[1], valores[2], &claves);
        uint64_t resultado = (strcmp(orden, "tdea-cifrar") == 0)
                           ? tdea_cifrar(valores[3], &claves)
                           : tdea_descifrar(valores[3], &claves);
        printf("%016llX\n", (unsigned long long)resultado);
        return EXIT_SUCCESS;
    }

    mostrar_uso(argv[0]);
    return EXIT_FAILURE;
}
