# Insecure Object Deserialization

> **ATTENZIONE: Questo progetto contiene VULNERABILITÀ INTENZIONALI a scopo didattico. NON UTILIZZARE in ambienti di produzione.**

## Un'analisi di vulnerabilità e mitigazioni

Questo progetto è basato su Quarkus 3.19 e richiede pertanto che abbiate installato sulla vostra macchina Java 21 e Maven 3.9.

Per testare le vulnerabilità e le relative mitigazioni, sono stati predisposti i seguenti componenti.

1. Servizio REST `/api/v1/deserialize` per la deserializzazione di oggetti Java binari
2. Servizio REST `/api/v1/deserialize-secure` per la mitigazione della deserializzazione sicura di oggetti Java binari
3. Servizio REST `/api/v1/deserialize-json` per la deserializzazione di oggetti JSON
4. Servizio REST `/api/v1/deserialize-json-secure` per la mitigazione della deserializzazione sicura di oggetti JSON
5. Servizio REST `/api/v1/deserialize-yaml` per la deserializzazione di oggetti YAML
6. Servizio REST `/api/v1/deserialize-yaml-secure` per la mitigazione della deserializzazione sicura di oggetti YAML
7. La classe `Exploit` per dimostrare l'esecuzione di codice malevolo
8. La classe `SafeClass` per dimostrare la deserializzazione sicura

Per eseguire alcuni test, è necessario ottenere i file della serializzazione delle due classi Exploit e SafeClass. Per farlo, eseguire il seguente comando Maven:

```shell
mvn test
```

L'esecuzione dei test farà in modo di generare all'interno della directory `target` del progetto i due file `exploit-payload-to-testing.ser` e `safe-payload-to-testing.ser`.

Per eseguire l'applicazione è sufficiente eseguire il comando `mvn quarkus:dev`

---

## Cosa è la Deserializzazione di Oggetti?

- Processo di conversione di dati serializzati (stream di byte, JSON, YAML) in oggetti
- Utilizzato per:
    - Persistenza di dati
    - Trasferimento di dati tra sistemi
    - API REST
    - Sessioni utente

---

## La Vulnerabilità

- [OWASP Top 10: A8:2017 - Insecure Deserialization](https://github.com/OWASP/www-project-top-ten/blob/master/2017/A8_2017-Insecure_Deserialization.md)
- OWASP Top 10: [A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)

- Rischi:
    - Esecuzione di codice remoto (RCE)
    - Attacchi denial-of-service
    - Bypass di controlli di accesso
    - Manipolazione dei dati

---

## Esempio: Exploiting Java Deserialization

```java
// Classe malevola
public class Exploit implements Serializable {
  static {
    try {
      ProcessBuilder processBuilder =
          new ProcessBuilder("sh", "-c", "echo \"Sei stato hackerato ;-)\" >> /tmp/hacked");
      processBuilder.start();
    } catch (Exception e) {
      e.printStackTrace();
    }
  }
}
```

---

## Vulnerabilità #1: Java Binary Serialization

```java
@POST
@Path("/deserialize")
@Consumes(MediaType.APPLICATION_OCTET_STREAM)
public Response deserialize(InputStream input) throws IOException, ClassNotFoundException {
  ObjectInputStream objectInputStream = new ObjectInputStream(input);

  // Vulnerabile! Qualsiasi oggetto può essere deserializzato
  Object obj = objectInputStream.readObject();
  return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
}
```

### Esempio di chiamata cURL

```bash
# NOTA: Questo esempio usa un file binario serialized-exploit.bin che contiene un oggetto Java serializzato
curl -X POST http://localhost:8080/api/v1/deserialize \
     -H "Content-Type: application/octet-stream" \
     --data-binary @target/exploit-payload-to-testing.ser
```

---

## Mitigazione #1: Filtri di Classe

```java
@POST
@Path("/deserialize-secure")
public Response deserializeSecure(InputStream input) throws IOException, ClassNotFoundException {
  ObjectInputStream objectInputStream = new ObjectInputStream(input);
  objectInputStream.setObjectInputFilter(info -> {
    if (info.serialClass() != null &&
        info.serialClass().getName().startsWith(SAFE_PACKAGE)) {
      return ObjectInputFilter.Status.ALLOWED;
    }
    return ObjectInputFilter.Status.REJECTED;
  });
  Object obj = objectInputStream.readObject();
  return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
}
```

### Esempio di chiamata cURL

```bash
# NOTA: Questo esempio usa un file binario serialized-safe.bin che contiene un oggetto SafeClass serializzato
curl -X POST http://localhost:8080/api/v1/deserialize-secure \
     -H "Content-Type: application/octet-stream" \
     --data-binary @target/safe-payload-to-testing.ser
```

---

## Vulnerabilità #2: JSON Deserialization

```java
@POST
@Path("/deserialize-json")
@Consumes(MediaType.APPLICATION_JSON)
public Response deserializeJson(String json) throws JsonProcessingException {
  ObjectMapper objectMapper = new ObjectMapper();

  // Vulnerabile! Deserializza qualsiasi oggetto
  objectMapper.activateDefaultTyping(
      BasicPolymorphicTypeValidator.builder().allowIfBaseType(Object.class).build(),
      ObjectMapper.DefaultTyping.NON_FINAL,
      JsonTypeInfo.As.PROPERTY);

  Object obj = objectMapper.readValue(json, Object.class);
  return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
}
```

### Esempio di chiamata cURL

```bash
# Esempio con payload malevolo che potrebbe sfruttare la vulnerabilità
curl -X POST \
  http://localhost:8080/api/v1/deserialize-json \
  -H "Content-Type: application/json" \
  -d '{"@class": "it.dontesta.labs.quarkus.poc.security.iod.evil.Exploit"}'
```

---

## Mitigazione #2: Validazione Tipi JSON

```java
@POST
@Path("/deserialize-json-secure")
@Consumes(MediaType.APPLICATION_JSON)
public Response deserializeJsonSecure(String json) {
  ObjectMapper objectMapper = new ObjectMapper();

  // Configura restrizioni
  objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
  
  // Quando si attiva FAIL_ON_TRAILING_TOKENS, l'ObjectMapper viene istruito a 
  // generare un'eccezione se trova qualsiasi contenuto aggiuntivo dopo la fine del 
  // documento JSON principale. Questo è un meccanismo di difesa che assicura che il 
  // JSON in input sia esattamente come previsto, senza dati estranei che potrebbero 
  // indicare un tentativo di manipolazione.
  objectMapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

  // Permetti solo tipi specifici
  objectMapper.activateDefaultTyping(
      BasicPolymorphicTypeValidator.builder()
          .allowIfBaseType(SAFE_PACKAGE)
          .build(),
      ObjectMapper.DefaultTyping.NON_FINAL
  );

  try {
    Object obj = objectMapper.readValue(json, Object.class);
    return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
  } catch (JsonProcessingException e) {
    return Response.serverError()
        .entity("Errore durante la deserializzazione: %s".formatted(e.getMessage())).build();
  }
}
```

### Esempio di chiamata cURL

```bash
# Esempio con oggetto SafeClass legittimo
curl -X POST \
  http://localhost:8080/api/v1/deserialize-json-secure \
  -H "Content-Type: application/json" \
  -d '{"@class": "it.dontesta.labs.quarkus.poc.security.iod.safe.SafeClass", "name": "Esempio sicuro", "value": 42}'

# Esempio con payload malevolo che potrebbe sfruttare la vulnerabilità
# ma viene bloccato
curl -X POST \
  http://localhost:8080/api/v1/deserialize-json-secure \
  -H "Content-Type: application/json" \
  -d '{"@class": "it.dontesta.labs.quarkus.poc.security.iod.evil.Exploit"}'

```

---

## Vulnerabilità #3: YAML Deserialization

```java
@POST
@Path("/deserialize-yaml")
@Consumes("application/x-yaml")
public Response deserializeYaml(String yaml) {
  Yaml yamlParser = new Yaml();

  // Vulnerabile! Deserializza qualsiasi oggetto
  Object obj = yamlParser.load(yaml);
  return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
}
```

### Esempio di chiamata cURL

```bash
# Esempio con payload YAML malevolo
curl -X POST \
  http://localhost:8080/api/v1/deserialize-yaml \
  -H "Content-Type: application/x-yaml" \
  -d '!!it.dontesta.labs.quarkus.poc.security.iod.evil.Exploit {}'
```

---

## Mitigazione #3: SafeConstructor per YAML

```java
@POST
@Path("/deserialize-yaml-secure")
@Consumes("application/x-yaml")
public Response deserializeYamlSecure(String yaml) {
  // Creazione di LoaderOptions per maggiore sicurezza
  LoaderOptions options = new LoaderOptions();
  options.setAllowRecursiveKeys(false);

  // Permette solo la deserializzazione della SafeClass
  Yaml yamlParser = new Yaml(new Constructor(SafeClass.class, options));
  SafeClass obj = yamlParser.load(yaml);

  return Response.ok("Deserialized: %s".formatted(obj.toString())).build();
}
```

### Esempio di chiamata cURL

```bash
# Esempio con SafeClass YAML
curl -X POST \
  http://localhost:8080/api/v1/deserialize-yaml-secure \
  -H "Content-Type: application/x-yaml" \
  -d 'name: "Esempio sicuro"
value: 42'
```

---

## Best Practices

1. **Non** deserializzare dati non fidati
2. Utilizzare filtri di classe espliciti
3. Implementare controlli di integrità (firme digitali)
4. Preferire formati alternativi (JSON, XML) con parser sicuri
5. Mantenere librerie aggiornate
6. Monitorare CVE relativi alle librerie di serializzazione

---

## Esempio di Dati Sicuri (YAML)

```yaml
# Esempio sicuro per SafeClass
name: "Esempio sicuro"
value: 42
```

---

## Risorse Utili

- [OWASP Deserialization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html)
- [OWASP A8:2017 - Insecure Deserialization](https://github.com/OWASP/Top10/blob/master/2017/en/0xa8-insecure-deserialization.md)
- [A08:2021 – Software and Data Integrity Failures](https://owasp.org/Top10/A08_2021-Software_and_Data_Integrity_Failures/)
- SANS Top 25 - Insecure Deserialization
- https://github.com/OWASP/CheatSheetSeries

---

## Conclusioni

- La deserializzazione insicura è un vettore di attacco critico
- Comprendere le vulnerabilità è fondamentale
- Implementare sempre le appropriate misure di sicurezza
- Preferire approcci sicuri a priori piuttosto che correggere dopo

---

## Disclaimer Importante

**Questo progetto è a scopo puramente DIDATTICO.** Contiene **VULNERABILITÀ INTENZIONALI** e **NON DEVE ESSERE UTILIZZATO IN AMBIENTI DI PRODUZIONE.**

La sicurezza delle applicazioni e dell'infrastruttura è un aspetto critico. In applicazioni reali, è fondamentale seguire le *best practices* di sicurezza, eseguire test di sicurezza approfonditi e utilizzare strumenti di sicurezza automatizzati in modo continuo per ridurre i rischi e proteggere i dati e i sistemi.

## Licenza

MIT License (see [LICENSE.md](LICENSE.md)).
