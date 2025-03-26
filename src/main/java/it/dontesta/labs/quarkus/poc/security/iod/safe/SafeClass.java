package it.dontesta.labs.quarkus.poc.security.iod.safe;

import java.io.Serial;
import java.io.Serializable;

/**
 * Classe sicura utilizzata per la deserializzazione negli esempi di sicurezza.
 * Questa classe implementa Serializable per consentire la serializzazione/deserializzazione
 * e contiene proprietà semplici che non presentano rischi di sicurezza.
 * <p>
 * Viene utilizzata come esempio di classe "sicura" nei test di deserializzazione
 * per dimostrare pattern corretti di gestione degli oggetti.
 */
public class SafeClass implements Serializable {
  /**
   * Serial version UID utilizzato per garantire la compatibilità durante la serializzazione.
   */
  @Serial
  private static final long serialVersionUID = -1485436558193290557L;

  /**
   * Nome dell'oggetto safe.
   */
  private String name;

  /**
   * Valore numerico associato all'oggetto.
   */
  private int value;

  /**
   * Costruttore predefinito senza parametri.
   * Necessario per la corretta deserializzazione.
   */
  public SafeClass() {
  }

  /**
   * Costruttore che inizializza tutti i campi dell'oggetto.
   *
   * @param name  il nome da assegnare all'oggetto
   * @param value il valore numerico da assegnare all'oggetto
   */
  public SafeClass(String name, int value) {
    this.name = name;
    this.value = value;
  }

  /**
   * Restituisce il nome dell'oggetto.
   *
   * @return il nome dell'oggetto
   */
  public String getName() {
    return name;
  }

  /**
   * Imposta il nome dell'oggetto.
   *
   * @param name il nuovo nome da assegnare
   */
  public void setName(String name) {
    this.name = name;
  }

  /**
   * Restituisce il valore numerico dell'oggetto.
   *
   * @return il valore numerico dell'oggetto
   */
  public int getValue() {
    return value;
  }

  /**
   * Imposta il valore numerico dell'oggetto.
   *
   * @param value il nuovo valore numerico da assegnare
   */
  public void setValue(int value) {
    this.value = value;
  }

  /**
   * Restituisce una rappresentazione testuale dell'oggetto.
   *
   * @return stringa che rappresenta l'oggetto con i suoi valori
   */
  @Override
  public String toString() {
    return "SafeClass{name='%s', value=%d}".formatted(name, value);
  }
}