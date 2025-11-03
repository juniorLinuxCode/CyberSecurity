#!/usr/bin/env python3
import sys
import os
import afl
from typing import List, Optional
# -----------------------------------------
# Definisci qui la funzione di test reale
# -----------------------------------------
def testFunction(values: List[int]) -> None:
    """
    Sostituisci il corpo di questa funzione con il tuo codice da fuzzare.
    `values` contiene TUTTI gli interi letti dallo stdin per questa iterazione.
    Esempio minimo: stampa (ma in un ambiente di fuzzing potresti voler evitare I/O costosi).
    """
    # esempio: mostra quanti valori e i primi 10
    print(f"testFunction called with {len(values)} values; first up to 10: {values[:10]}")
def main() -> None:
    try:
        in_str = sys.stdin.read()
        if not in_str:
            return
        # Splitta su whitespace e prova a convertire ciascun token in intero.
        tokens = in_str.strip().split()
        if not tokens:
            return
        values: List[int] = []
        for t in tokens:
            try:
                values.append(int(t))
            except ValueError:
                # ignora token non interi (comportamento comune durante fuzzing)
                continue
        if not values:
            # nessun intero valido trovato
            return
        # --------------------------
        # Modalità 1 (default): passa TUTTI i valori a testFunction
        # --------------------------
        testFunction(values)
        # --------------------------
        # Modalità 2 (opzionale): processa valori a blocchi (chunk) di dimensione CHUNK_SIZE.
        # Scommenta se vuoi richiamare testFunction per ogni gruppo di N interi.
        # --------------------------
        # CHUNK_SIZE: se vuoi il comportamento "3 per volta" usa 3; None per disabilitare
        # CHUNK_SIZE: Optional[int] = 3
        # if CHUNK_SIZE:
        #     for i in range(0, len(values), CHUNK_SIZE):
        #         chunk = values[i:i+CHUNK_SIZE]
        #         if len(chunk) == CHUNK_SIZE:
        #             # se vuoi anche gli ultimi chunk incompleti, rimuovi la condizione
        #             testFunction(chunk)
    except Exception:
        # evita che eccezioni non gestite terminino il processo di fuzzing
        return
if __name__ == "__main__":
    # Inizializza python-afl; mantiene il processo pronto per il fuzzer
    afl.init()
    main()
    # esci in modo "pulito" per AFL
    os._exit(0)








