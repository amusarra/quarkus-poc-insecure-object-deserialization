package it.dontesta.labs.quarkus.poc.security.iod.ws.v1;

import com.fasterxml.jackson.annotation.JsonTypeInfo;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import it.dontesta.labs.quarkus.poc.security.iod.safe.SafeClass;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;
import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.Constructor;

/**
 * Classe risorsa che dimostra pattern di deserializzazione di oggetti sicuri e insicuri.
 * Questa classe contiene endpoint che mostrano vulnerabilità relative alla deserializzazione
 * insicura attraverso diversi formati (serializzazione Java, JSON e YAML)
 * insieme ad alternative di implementazione sicura.
 * <p>
 * AVVERTENZA DI SICUREZZA: Gli endpoint insicuri in questa classe sono intenzionalmente vulnerabili
 * e dovrebbero essere utilizzati solo a scopo educativo.
 */
@Path("/v1")
public class InsecureObjectDeserializationResource {

  /**
   * Package che contiene classi considerate sicure per la deserializzazione.
   */
  private static final String SAFE_PACKAGE = "it.dontesta.labs.quarkus.poc.security.iod.safe";

  /**
   * Dimostra la deserializzazione insicura di oggetti Java.
   * VULNERABILITÀ DI SICUREZZA: Questo endpoint deserializza qualsiasi oggetto Java senza
   * validazione, rendendolo vulnerabile ad attacchi di deserializzazione.
   *
   * @param input Lo stream di input contenente l'oggetto Java serializzato
   * @return Response contenente il nome della classe dell'oggetto deserializzato
   * @throws IOException            Se si verifica un errore di I/O durante la deserializzazione
   * @throws ClassNotFoundException Se la classe dell'oggetto serializzato non può essere trovata
   */
  @POST
  @Path("/deserialize")
  @Consumes(MediaType.APPLICATION_OCTET_STREAM)
  public Response deserialize(InputStream input) throws IOException, ClassNotFoundException {
    try (ObjectInputStream objectInputStream = new ObjectInputStream(input)) {
      // Pericolo! Qualsiasi oggetto può essere deserializzato
      Object obj = objectInputStream.readObject();
      return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
    }
  }

  /**
   * Dimostra la deserializzazione sicura di oggetti Java con filtraggio delle classi.
   * Utilizza ObjectInputFilter per limitare la deserializzazione alle classi di un package sicuro.
   *
   * @param input Lo stream di input contenente l'oggetto Java serializzato
   * @return Response contenente il nome della classe dell'oggetto deserializzato
   * @throws IOException            Se si verifica un errore di I/O durante la deserializzazione
   * @throws ClassNotFoundException Se la classe dell'oggetto serializzato non può essere trovata
   */
  @POST
  @Path("/deserialize-secure")
  @Consumes(MediaType.APPLICATION_OCTET_STREAM)
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

  /**
   * Dimostra la deserializzazione JSON insicura con Jackson.
   * VULNERABILITÀ DI SICUREZZA: Questo endpoint abilita la gestione dei tipi polimorfi,
   * permettendo la deserializzazione di classi arbitrarie basate sulle informazioni di tipo nel JSON.
   *
   * @param json La stringa JSON da deserializzare
   * @return Response contenente il nome della classe dell'oggetto deserializzato
   * @throws JsonProcessingException Se si verifica un errore durante l'elaborazione del JSON
   */
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
    obj.toString();

    return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
  }

  /**
   * Dimostra la deserializzazione JSON sicura con Jackson.
   * Utilizza validatori di tipo per limitare la deserializzazione alle classi di un package sicuro.
   *
   * @param json La stringa JSON da deserializzare
   * @return Response contenente il nome della classe dell'oggetto deserializzato o un messaggio di errore
   */
  @POST
  @Path("/deserialize-json-secure")
  @Consumes(MediaType.APPLICATION_JSON)
  public Response deserializeJsonSecure(String json) {
    ObjectMapper objectMapper = new ObjectMapper();

    // Disabilita la possibilità di deserializzare oggetti arbitrari
    objectMapper.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);

    // Quando si attiva FAIL_ON_TRAILING_TOKENS, l'ObjectMapper viene istruito a
    // generare un'eccezione se trova qualsiasi contenuto aggiuntivo dopo la fine del
    // documento JSON principale. Questo è un meccanismo di difesa che assicura che il
    // JSON in input sia esattamente come previsto, senza dati estranei che potrebbero
    // indicare un tentativo di manipolazione.
    objectMapper.enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);

    // Blocca la deserializzazione di classi pericolose
    // Solo classi note
    objectMapper.activateDefaultTyping(
        BasicPolymorphicTypeValidator.builder()
            .allowIfSubType(SAFE_PACKAGE)  // Usa allowIfSubType invece di allowIfBaseType
            .build(),
        ObjectMapper.DefaultTyping.NON_FINAL,
        JsonTypeInfo.As.PROPERTY
    );

    try {
      Object obj = objectMapper.readValue(json, Object.class);
      return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
    } catch (JsonProcessingException e) {
      return Response.serverError()
          .entity("Errore durante la deserializzazione: %s".formatted(e.getMessage())).build();
    }
  }

  /**
   * Dimostra la deserializzazione YAML insicura.
   * VULNERABILITÀ DI SICUREZZA: Questo endpoint deserializza qualsiasi oggetto da YAML senza
   * restrizioni, permettendo potenzialmente l'esecuzione di codice arbitrario.
   *
   * @param yaml La stringa YAML da deserializzare
   * @return Response contenente il nome della classe dell'oggetto deserializzato
   */
  @POST
  @Path("/deserialize-yaml")
  @Consumes("application/x-yaml")
  public Response deserializeYaml(String yaml) {
    Yaml yamlParser = new Yaml();

    // Vulnerabile! Deserializza qualsiasi oggetto
    Object obj = yamlParser.load(yaml);
    return Response.ok("Deserialized: %s".formatted(obj.getClass().getName())).build();
  }

  /**
   * Dimostra la deserializzazione YAML sicura.
   * Utilizza un costruttore specifico per limitare la deserializzazione al tipo SafeClass
   * e limita le chiavi ricorsive per prevenire attacchi denial-of-service.
   *
   * @param yaml La stringa YAML da deserializzare
   * @return Response contenente la rappresentazione in stringa dell'oggetto deserializzato
   */
  @POST
  @Path("/deserialize-yaml-secure")
  @Consumes("application/x-yaml")
  @Produces(MediaType.TEXT_PLAIN)
  public Response deserializeYamlSecure(String yaml) {
    // Creazione di LoaderOptions per maggiore sicurezza
    LoaderOptions options = new LoaderOptions();

    // Evita attacchi basati su chiavi ricorsive
    options.setAllowRecursiveKeys(false);

    // Permette solo la deserializzazione della SafeClass
    Yaml yamlParser = new Yaml(new Constructor(SafeClass.class, options));
    SafeClass obj = yamlParser.load(yaml);

    return Response.ok("Deserialized: %s".formatted(obj.toString())).build();
  }
}