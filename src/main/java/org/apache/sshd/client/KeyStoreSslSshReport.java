package org.apache.sshd.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.Date;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.security.auth.x500.X500Principal;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.function.FailableBiConsumer;
import org.apache.commons.lang3.function.FailableBiFunction;
import org.apache.commons.lang3.function.FailableConsumer;
import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.function.FailableRunnable;
import org.apache.commons.lang3.math.NumberUtils;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.future.ConnectFuture;
import org.apache.sshd.client.keyverifier.AcceptAllServerKeyVerifier;
import org.apache.sshd.client.keyverifier.ServerKeyVerifier;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.auth.BasicCredentialsImpl;
import org.apache.sshd.common.auth.BasicCredentialsProvider;
import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.config.keys.FilePasswordProvider;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.future.VerifiableFuture;
import org.apache.sshd.common.session.Session;
import org.apache.sshd.common.session.SessionContext;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.putty.PuttyKeyUtils;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.client.fs.SftpFileSystem;
import org.d2ab.function.ObjIntPredicate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import com.google.common.net.HostAndPort;
import com.google.common.reflect.Reflection;

import io.github.toolfactory.narcissus.Narcissus;

public class KeyStoreSslSshReport {

	private static final String VALUE = "value";

	private static final String INITIALIZED = "initialized";

	private static final String DELEGATE = "delegate";

	private static final String PASSWORD = "password";

	private static final Logger LOG = LoggerFactory.getLogger(KeyStoreSslSshReport.class);

	private static class IH implements InvocationHandler {

		private Map<Object, Object> map = null;

		@Override
		public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
			//
			final String name = getName(method);
			//
			if (proxy instanceof ObjectMap) {
				//
				if (Objects.equals(name, "getObject") && args != null && args.length > 0) {
					//
					return get(map, ArrayUtils.get(args, 0));
					//
				} else if (Objects.equals(name, "setObject") && args != null && args.length > 1) {
					//
					put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), ArrayUtils.get(args, 0),
							ArrayUtils.get(args, 1));
					//
					return null;
					//
				} // if
					//
			} // if
				//
			throw new Throwable(name);
			//
		}

	}

	public static void main(final String[] args) throws Exception {
		//
		final Map<String, String> map = toMap(args);
		//
		if (containsKey(map, "config")) {
			//
			perform(parse(newDocumentBuilder(DocumentBuilderFactory.newInstance()),
					testAndApply(Objects::nonNull, get(map, "config"), File::new, null)),
					newXPath(XPathFactory.newInstance()));
			//
		} else {
			//
			final IH ih = new IH();
			//
			final ObjectMap objectMap = Reflection.newProxy(ObjectMap.class, ih);
			//
			if (objectMap != null) {
				//
				objectMap.setObject(HostAndPort.class, testAndApply(Objects::nonNull, get(map, "host"),
						x -> HostAndPort.fromParts(x, NumberUtils.toInt(get(map, "port"), 22)), null));
				//
				objectMap.setObject(BasicCredentialsProvider.class,
						new BasicCredentialsImpl(get(map, "user"), get(map, PASSWORD)));
				//
				objectMap.setObject(File.class,
						testAndApply(StringUtils::isNotBlank, get(map, "keyPath"), File::new, null));
				//
				objectMap.setObject(char[].class, toCharArray(get(map, "keyStorePassword")));
				//
			} // if
				//
			info(LOG, perform(Reflection.newProxy(ObjectMap.class, ih), null, get(map, "file"), get(map, "url"), null));
			//
		} // if
			//
	}

	private static DocumentBuilder newDocumentBuilder(final DocumentBuilderFactory instance)
			throws ParserConfigurationException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "fSecurityManager")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.newDocumentBuilder() : null;
		//
	}

	private static Document parse(final DocumentBuilder instance, final File file) throws SAXException, IOException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "domParser")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return (field == null || Narcissus.getField(instance, field) != null) && file != null && file.getPath() != null
				&& exists(file) && file.isFile() ? instance.parse(file) : null;
		//
	}

	private static XPath newXPath(final XPathFactory instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "_featureManager")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.newXPath() : null;
		//
	}

	private static void perform(final Document document, final XPath xp) throws Exception {
		//
		final NodeList nodeList = cast(NodeList.class, evaluate(xp, "/*/host", document, XPathConstants.NODESET));
		//
		Node node = null;
		//
		Iterable<String> urls = null;
		//
		Map<String, String> map = null;
		//
		Map<String, Entry<String, Date>> entries = null;
		//
		Map<HostAndPort, byte[]> byteArrayMap = null;
		//
		IH ih = null;
		//
		ObjectMap objectMap = null;
		//
		for (int i = 0; nodeList != null && i < nodeList.getLength(); i++) {
			//
			if ((urls = getStrings(cast(NodeList.class,
					evaluate(xp, "urls/url", node = nodeList.item(i), XPathConstants.NODESET)))) == null
					|| entrySet(map = getKeyStores(
							cast(NodeList.class, evaluate(xp, "keyStores/keyStore", node, XPathConstants.NODESET)),
							xp)) == null) {
				//
				continue;
				//
			} // if
				//
			for (final Entry<String, String> entry : entrySet(map)) {
				//
				for (final String url : urls) {
					//
					final Node n = node;
					//
					if ((objectMap = Reflection.newProxy(ObjectMap.class, ih = new IH())) != null) {
						//
						objectMap.setObject(HostAndPort.class,
								testAndApply(Objects::nonNull, Objects.toString(evaluate(xp, "ip", node)),
										x -> HostAndPort.fromParts(x,
												NumberUtils.toInt(Objects.toString(evaluate(xp, "port", n)), 22)),
										null));
						//
						objectMap.setObject(BasicCredentialsProvider.class, new BasicCredentialsImpl(
								Objects.toString(evaluate(xp, "user", node)),
								getTextContent(cast(Node.class, evaluate(xp, PASSWORD, node, XPathConstants.NODE)))));
						//
						objectMap.setObject(File.class, testAndApply(StringUtils::isNotBlank,
								Objects.toString(evaluate(xp, "keyPath", node)), File::new, null));
						//
						objectMap.setObject(char[].class, toCharArray(getValue(entry)));
						//
					} // if
						//
					info(LOG,
							perform(Reflection.newProxy(ObjectMap.class, ih),
									byteArrayMap = ObjectUtils.getIfNull(byteArrayMap, LinkedHashMap::new),
									getKey(entry), url, entries = ObjectUtils.getIfNull(entries, LinkedHashMap::new)));
					//
				} // for
					//
			} // if
				//
		} // if
			//
	}

	private static Map<String, String> getKeyStores(final NodeList instance, final XPath xp)
			throws XPathExpressionException {
		//
		Map<String, String> map = null;
		//
		Node node = null;
		//
		for (int i = 0; instance != null && i < instance.getLength(); i++) {
			//
			put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new),
					Objects.toString(evaluate(xp, "path", node = instance.item(i))),
					getTextContent(cast(Node.class, evaluate(xp, PASSWORD, node, XPathConstants.NODE))));
			//
		} // for
			//
		return map;
		//
	}

	private static String getTextContent(final Node instance) {
		return instance != null ? instance.getTextContent() : null;
	}

	private static Iterable<String> getStrings(final NodeList instance) {
		//
		List<String> list = null;
		//
		for (int i = 0; instance != null && i < instance.getLength(); i++) {
			//
			add(list = ObjectUtils.getIfNull(list, ArrayList::new), getTextContent(instance.item(i)));
			//
		} // for
			//
		return list;
		//
	}

	private static <E> void add(final Collection<E> instance, final E item) {
		if (instance != null) {
			instance.add(item);
		}
	}

	private static Object evaluate(final XPath instance, final String string, final Object object)
			throws XPathExpressionException {
		return instance != null && object != null ? instance.evaluate(string, object) : null;
	}

	private static Object evaluate(final XPath instance, final String string, final Object object, final QName qName)
			throws XPathExpressionException {
		return instance != null && object != null ? instance.evaluate(string, object, qName) : null;
	}

	private static boolean containsKey(final Map<?, ?> instance, final Object key) {
		return instance != null && instance.containsKey(key);
	}

	private static <T, U, E extends Exception> void testAndAccept(final BiPredicate<T, U> predicate, final T t,
			final U u, final FailableBiConsumer<T, U, E> consumer) throws E {
		if (predicate != null && predicate.test(t, u) && consumer != null) {
			consumer.accept(t, u);
		}
	}

	private static boolean exists(final File instance) {
		return instance != null && instance.getPath() != null && instance.exists();
	}

	private static boolean isFile(final File instance) {
		return instance != null && instance.getPath() != null && instance.isFile();
	}

	private static Path toPath(final File instance) {
		return instance != null && instance.getPath() != null ? instance.toPath() : null;
	}

	private static Collection<KeyPair> loadKeyPairs(final KeyPairResourceLoader instance, final SessionContext session,
			final Path path, final FilePasswordProvider passwordProvider, final OpenOption... options)
			throws IOException, GeneralSecurityException {
		return instance != null ? instance.loadKeyPairs(session, path, passwordProvider, options) : null;
	}

	private static <T, U, R, E extends Exception> R testAndApply(final BiPredicate<T, U> predicate, final T t,
			final U u, final FailableBiFunction<T, U, R, E> functionTrue,
			final FailableBiFunction<T, U, R, E> functionFalse) throws E {
		return predicate != null && predicate.test(t, u) ? apply(functionTrue, t, u) : apply(functionFalse, t, u);
	}

	private static <T, U, R, E extends Exception> R apply(final FailableBiFunction<T, U, R, E> instance, final T t,
			final U u) throws E {
		return instance != null ? instance.apply(t, u) : null;
	}

	private static Path getPath(final FileSystem instance, final String first, final String... more) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(first), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(first, field) != null ? instance.getPath(first, more) : null;
		//
	}

	private static SftpFileSystem createSftpFileSystem(final SftpClientFactory instnace, final ClientSession session)
			throws IOException {
		return instnace != null ? instnace.createSftpFileSystem(session) : null;
	}

	private static ConnectFuture connect(final ClientSessionCreator instance, final String username, final String host,
			final int port) throws IOException {
		return instance != null ? instance.connect(username, host, port) : null;
	}

	private static AuthFuture auth(final ClientSession instance) throws IOException {
		return instance != null ? instance.auth() : null;
	}

	private static <T, E extends Exception> void testAndAccept(final Predicate<T> predicate, final T value,
			final FailableConsumer<T, E> consumer) throws E {
		if (test(predicate, value)) {
			accept(consumer, value);
		}
	}

	private static <T, E extends Exception> void accept(final FailableConsumer<T, E> instance, final T value) throws E {
		if (instance != null) {
			instance.accept(value);
		}
	}

	private static void addPasswordIdentity(final ClientAuthenticationManager instance, final String password) {
		if (instance != null) {
			instance.addPasswordIdentity(password);
		}
	}

	private static void setServerKeyVerifier(final ClientAuthenticationManager instance,
			final ServerKeyVerifier serverKeyVerifier) {
		if (instance != null) {
			instance.setServerKeyVerifier(serverKeyVerifier);
		}
	}

	private static void start(final SshClient instance) {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "state")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || (Narcissus.getField(instance, field)) != null) {
			//
			instance.start();
			//
		} // if
			//
	}

	private static boolean isSuccess(final AuthFuture instance) {
		return instance != null && instance.isSuccess();
	}

	private static <S extends Session> S getSession(final SessionHolder<S> instance) {
		return instance != null ? instance.getSession() : null;
	}

	private static <T> T verify(final VerifiableFuture<T> instnace) throws IOException {
		return instnace != null ? instnace.verify() : null;
	}

	private static <E extends Exception> void testAndRun(final boolean condition, final FailableRunnable<E> runnable)
			throws E {
		if (condition && runnable != null) {
			runnable.run();
		}
	}

	private static <T> T iif(final boolean condition, final T valueTrue, final T valueFalse) {
		return condition ? valueTrue : valueFalse;
	}

	private static long longValue(final Number instance, final long defaultValue) {
		return instance != null ? instance.longValue() : defaultValue;
	}

	private static interface ObjectMap {

		<T> T getObject(final Class<?> clz);

		<T> void setObject(final Class<T> clz, final T value);

	}

	private static Result perform(final ObjectMap objectMap, final Map<HostAndPort, byte[]> byteArrayMap,
			final String keyStoreFile, final String url, final Map<String, Entry<String, Date>> entries)
			throws Exception {
		//
		final HostAndPort hostAndPort = objectMap != null ? objectMap.getObject(HostAndPort.class) : null;
		//
		final BasicCredentialsProvider basicCredentialsProvider = objectMap != null
				? objectMap.getObject(BasicCredentialsProvider.class)
				: null;
		//
		byte[] bs = get(byteArrayMap, hostAndPort);
		//
		if (bs == null) {
			//
			put(byteArrayMap, hostAndPort, bs = readByteArray(hostAndPort, basicCredentialsProvider,
					objectMap != null ? objectMap.getObject(File.class) : null, keyStoreFile));
			//
		} // if
			//
		Map<String, X509Certificate> map = null;
		//
		try (final InputStream is = testAndApply(Objects::nonNull, bs, ByteArrayInputStream::new, null)) {
			//
			final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
			//
			testAndRun(is != null,
					() -> load(keyStore, is, objectMap != null ? objectMap.getObject(char[].class) : null));
			//
			String alias, lcs = null;
			//
			Certificate certificate = null;
			//
			X509Certificate x509Certificate = null;
			//
			Date notAfter = null;
			//
			final Enumeration<String> aliases = aliases(keyStore);
			//
			while (hasMoreElements(aliases)) {
				//
				if ((isCertificateEntry(keyStore, alias = nextElement(aliases)) || isKeyEntry(keyStore, alias))
						&& (certificate = getCertificate(keyStore, alias)) instanceof X509Certificate
						&& (x509Certificate = (X509Certificate) certificate) != null
						&& isValid(DomainValidator.getInstance(),
								lcs = longestCommonSubstring(getName(getSubjectX500Principal(x509Certificate)), url))
						&& ((notAfter = getNotAfter(
								get(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), lcs))) == null
								|| ObjectUtils.compare(getNotAfter(x509Certificate), notAfter) > 0)) {
					//
					put(map, lcs, x509Certificate);
					//
				} // if
					//
			} // while
				//
		} // try
			//
		final String longest = orElse(max(stream(keySet(map)), Comparator.comparingInt(StringUtils::length)), "");
		//
		final Result result = perform(url,
				collect(filter(stream(entrySet(map)), x -> Objects.equals(getKey(x), longest)),
						Collectors.toMap(x -> getKey(x), x -> getValue(x))),
				entries);
		//
		if (result != null) {
			//
			result.hostAndPort = hostAndPort;
			//
			result.usernameHolder = basicCredentialsProvider;
			//
			result.keyStoreFile = keyStoreFile;
			//
		} // if
			//
		return result;
		//
	}

	private static byte[] readByteArray(final HostAndPort hostAndPort,
			final BasicCredentialsProvider basicCredentialsProvider, final File key, final String keyStoreFile)
			throws Exception {
		//
		byte[] bs = null;
		//
		try (final SshClient sshClient = SshClient.setUpDefaultClient()) {
			//
			setServerKeyVerifier(sshClient, AcceptAllServerKeyVerifier.INSTANCE);
			//
			start(sshClient);
			//
			try (final ClientSession clientSession = testAndApply(
					(a, b) -> Boolean.logicalAnd(a != null, StringUtils.isNotEmpty(b)),
					getUsername(basicCredentialsProvider), getHost(hostAndPort), (a,
							b) -> getSession(verify(connect(sshClient, a, b,
									hostAndPort != null && hostAndPort.hasPort() ? hostAndPort.getPort() : 22))),
					null)) {
				//
				testAndAccept(Objects::nonNull,
						basicCredentialsProvider != null ? basicCredentialsProvider.getPassword() : null,
						x -> addPasswordIdentity(clientSession, x));
				//
				testAndAccept(x -> Boolean.logicalAnd(exists(x), isFile(x)), key,
						x -> loadKeyPairs(PuttyKeyUtils.DEFAULT_INSTANCE, null, toPath(x), null));
				//
				try (final SftpFileSystem sftpFileSystem = isSuccess(verify(auth(clientSession)))
						? createSftpFileSystem(SftpClientFactory.instance(), clientSession)
						: null;
						final InputStream is = testAndApply(x -> x != null && StringUtils.isNotBlank(keyStoreFile),
								getPath(sftpFileSystem, keyStoreFile), Files::newInputStream, null);
						final ByteArrayOutputStream baos = new ByteArrayOutputStream()) {
					//
					testAndAccept((a, b) -> Boolean.logicalAnd(a != null, b != null), is, baos, IOUtils::copy);
					//
					bs = baos.toByteArray();
					//
				} // try
					//
			} // try
				//
		} // try
			//
		return bs;
		//
	}

	private static String getUsername(final UsernameHolder instance) {
		return instance != null ? instance.getUsername() : null;
	}

	private static String getHost(final HostAndPort instance) {
		return instance != null ? instance.getHost() : null;
	}

	private static void info(final Logger logger, final Result result) {
		//
		DateFormat df = null;
		//
		final Long difference = result != null ? result.difference : null;
		//
		final String padding = iif(longValue(difference, 0) > 0, StringUtils.repeat(' ', 2), "");
		//
		info(LOG, "Host    {}={}", padding,
				StringUtils.defaultString(getHost(result != null ? result.hostAndPort : null)));
		//
		info(LOG, "User    {}={}", padding,
				StringUtils.defaultString(getUsername(result != null ? result.usernameHolder : null)));
		//
		info(LOG, "File    {}={}", padding, StringUtils.defaultString(result != null ? result.keyStoreFile : null));
		//
		info(logger, "URL     {}={}", padding, StringUtils.defaultString(result != null ? result.url : null));
		//
		Entry<String, Date> entry = result != null ? result.keyStoreDate : null;
		//
		info(logger, "KeyStore{}={} {}", padding, StringUtils.defaultString(getKey(entry)),
				StringUtils.defaultString(
						format(df = ObjectUtils.getIfNull(df, () -> new SimpleDateFormat("yyyy-MM-dd HH:mm:ss")),
								getValue(entry))));
		//
		info(logger, "HTTPS   {}={} {}", padding,
				StringUtils.defaultString(getKey(entry = result != null ? result.urlDate : null)),
				StringUtils.defaultString(format(df, getValue(entry))));
		//
		if (longValue(difference, 0) > 0) {
			//
			info(logger, "Difference={}",
					DurationFormatUtils.formatDurationWords(longValue(difference, 0), false, false));
			//
		} // if
			//
	}

	private static class Result {

		private HostAndPort hostAndPort;

		private UsernameHolder usernameHolder;

		@Target(ElementType.FIELD)
		@Retention(RetentionPolicy.RUNTIME)
		private @interface Note {
			String value();
		}

		@Note("Key Store File")
		private String keyStoreFile;

		private String url;

		@Note("Key Store Date")
		private Entry<String, Date> keyStoreDate;

		private Entry<String, Date> urlDate;

		private Long difference;

	}

	private static Result perform(final String url, final Map<String, X509Certificate> map,
			final Map<String, Entry<String, Date>> entries) throws IOException {
		//
		final Result result = new Result();
		//
		result.url = url;
		//
		X509Certificate x509Certificate = null;
		//
		Entry<String, Date> temp = null;
		//
		if (entrySet(map) != null) {
			//
			for (final Entry<String, X509Certificate> entry : entrySet(map)) {
				//
				if ((x509Certificate = getValue(entry)) == null) {
					//
					continue;
					//
				} // if
					//
				if ((temp = get(entries, url)) == null) {
					//
					put(entries, url, temp = getEntry(url));
					//
				} // if
					//
				result.urlDate = Pair.of(getKey(temp), getValue(temp));
				//
				result.difference = substract(getValue(temp),
						getValue(result.keyStoreDate = Pair.of(getKey(entry), getNotAfter(x509Certificate))));
				//
			} // for
				//
		} // if
			//
		return result;
		//
	}

	private static Long substract(final Date a, final Date b) {
		return a != null && b != null ? Long.valueOf(a.getTime() - b.getTime()) : null;
	}

	private static void info(final Logger instance, final String format, final Object... arguments) {
		if (instance != null) {
			instance.info(format, arguments);
		}
	}

	private static X500Principal getSubjectX500Principal(final X509Certificate instance) {
		return instance != null ? instance.getSubjectX500Principal() : null;
	}

	private static Entry<String, Date> getEntry(final String url) throws IOException {
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(url), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final HttpsURLConnection httpsURLConnection = cast(HttpsURLConnection.class,
				openConnection(testAndApply(x -> x != null && (field == null || Narcissus.getField(x, field) != null),
						url, URL::new, null)));
		//
		connect(httpsURLConnection);
		//
		final Certificate[] certificates = getServerCertificates(httpsURLConnection);
		//
		final DomainValidator domainValidator = DomainValidator.getInstance();
		//
		final List<Certificate> list = collect(
				filter(testAndApply(Objects::nonNull, certificates, Arrays::stream, null),
						x -> isValid(domainValidator,
								longestCommonSubstring(url,
										getName(getSubjectX500Principal(cast(X509Certificate.class, x)))))),
				Collectors.toList());
		//
		X509Certificate x509Certificate = null;
		//
		String name = null;
		//
		Date date = null;
		//
		for (int i = 0; i < size(list); i++) {
			//
			if (date != null) {
				//
				throw new IllegalStateException();
				//
			} // if
				//
			name = StringUtils.substringAfter(
					getName(getSubjectX500Principal(x509Certificate = cast(X509Certificate.class, get(list, i)))), '=');
			//
			date = getNotAfter(x509Certificate);
			//
		} // for
			//
		disconnect(httpsURLConnection);
		//
		return Pair.of(name, date);
		//
	}

	private static Date getNotAfter(final X509Certificate instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "info")), Collectors.toList()),
				x -> get(x, 0), null);

		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getNotAfter() : null;
		//
	}

	private static void disconnect(final HttpsURLConnection instance) {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.disconnect();
			//
		} // if
			//
	}

	private static void connect(final HttpsURLConnection instance) throws IOException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			instance.connect();
			//
		} // if
			//
	}

	private static Certificate[] getServerCertificates(final HttpsURLConnection instance)
			throws SSLPeerUnverifiedException {
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), DELEGATE)), Collectors.toList()),
				x -> get(x, 0), null);

		//
		return instance != null && (field == null || Narcissus.getField(instance, field) != null)
				? instance.getServerCertificates()
				: null;
		//
	}

	private static <T> T cast(final Class<T> clz, final Object instance) {
		return clz != null && clz.isInstance(instance) ? clz.cast(instance) : null;
	}

	private static URLConnection openConnection(final URL instance) throws IOException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "handler")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.openConnection() : null;
		//
	}

	private static Certificate getCertificate(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null || alias == null) {
			//
			return null;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return null;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(alias), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(alias, field) == null) {
			//
			return null;
			//
		} // if
			//
		return instance.getCertificate(alias);
		//
	}

	private static boolean isKeyEntry(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null || alias == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(alias), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(alias, field) == null) {
			//
			return false;
			//
		} // if
			//
		return instance.isKeyEntry(alias);
		//
	}

	private static boolean isCertificateEntry(final KeyStore instance, final String alias) throws KeyStoreException {
		//
		if (instance == null || alias == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(alias), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(alias, field) == null) {
			//
			return false;
			//
		} // if
			//
		return instance.isCertificateEntry(alias);
		//
	}

	private static boolean hasMoreElements(final Enumeration<?> instance) {
		return instance != null && instance.hasMoreElements();
	}

	private static <E> E nextElement(final Enumeration<E> instance) {
		return instance != null ? instance.nextElement() : null;
	}

	private static Enumeration<String> aliases(final KeyStore instance) throws KeyStoreException {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), INITIALIZED)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null
				|| (Objects.equals(field.getType(), Boolean.TYPE)) && !Narcissus.getBooleanField(instance, field)) {
			//
			return null;
			//
		} // if
			//
		return instance.aliases();
		//
	}

	private static boolean isValid(final DomainValidator instance, final String domain) {
		//
		if (instance == null) {
			//
			return false;
			//
		} // if
			//
		Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "domainRegex")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field != null && Narcissus.getField(instance, field) == null) {
			//
			return false;
			//
		} // if
			//
		if ((field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(domain), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null)) != null && Narcissus.getField(domain, field) == null) {
			//
			return false;
			//
		} // if
			//
		return domain != null && instance.isValid(domain);
		//
	}

	private static void load(final KeyStore instance, final InputStream stream, final char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		//
		if (instance == null) {
			//
			return;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "keyStoreSpi")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (field == null || Narcissus.getField(instance, field) != null) {
			//
			if (stream != null && stream.markSupported()) {
				//
				final byte[] bs = IOUtils.toByteArray(stream);
				//
				if (bs == null || bs.length == 0) {
					//
					return;
					//
				} // if
					//
				stream.reset();
				//
			} // if
				//
			instance.load(stream, password);
			//
		} // if
			//
	}

	private static <T> T orElse(final Optional<T> instance, final T other) {
		return instance != null ? instance.orElse(other) : other;
	}

	private static <T> Optional<T> max(final Stream<T> instance, final Comparator<? super T> comparator) {
		return instance != null ? instance.max(comparator) : null;
	}

	private static <K, V> Collection<Entry<K, V>> entrySet(final Map<K, V> instance) {
		return instance != null ? instance.entrySet() : null;
	}

	private static <K> Set<K> keySet(final Map<K, ?> instance) {
		return instance != null ? instance.keySet() : null;
	}

	private static String format(final DateFormat instance, final Date date) {
		//
		if (instance == null || date == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "calendar")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.format(date) : null;
		//
	}

	private static char[] toCharArray(final String instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.toCharArray() : null;
		//
	}

	private static <V> V get(final Map<?, V> instance, final Object key) {
		return instance != null ? instance.get(key) : null;
	}

	private static Map<String, String> toMap(final String... ss) {
		//
		Map<String, String> map = null;
		//
		Entry<String, String> entry = null;
		//
		for (int i = 0; i < length(ss); i++) {
			//
			if ((entry = toEntry(ArrayUtils.get(ss, i))) == null) {
				//
				continue;
				//
			} // if
				//
			put(map = ObjectUtils.getIfNull(map, LinkedHashMap::new), getKey(entry), getValue(entry));
			//
		} // for
			//
		return map;
		//
	}

	private static Entry<String, String> toEntry(final String string) {
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(string), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		if (string != null && field != null && Narcissus.getField(string, field) == null) {
			//
			return null;
			//
		} // if
			//
		if (Objects.equals(string, "=")) {
			//
			return Pair.of("", "");
			//
		} else if (string != null && string.length() == 2 && string.charAt(0) == '=') {
			//
			return Pair.of("", string.substring(1, string.length()));
			//
		} else if (string != null && string.length() == 2 && string.charAt(string.length() - 1) == '=') {
			//
			return Pair.of(string.substring(0, string.length() - 1), "");
			//
		} else if (string != null && string.indexOf('=') >= 0 && string.indexOf('=') == string.lastIndexOf('=')) {
			//
			return Pair.of(StringUtils.substringBefore(string, '='), StringUtils.substringAfter(string, '='));
			//
		} else if (string != null && string.length() > 2 && string.indexOf('=') != string.lastIndexOf('=')) {
			//
			return Pair.of(StringUtils.substring(string, 0, string.indexOf('=')),
					StringUtils.substring(string, string.indexOf('=') + 1));
			//
		} // if
			//
		return null;
		//
	}

	private static int length(final Object[] instance) {
		return instance != null ? instance.length : 0;
	}

	private static <K> K getKey(final Entry<K, ?> instance) {
		return instance != null ? instance.getKey() : null;
	}

	private static <V> V getValue(final Entry<?, V> instance) {
		return instance != null ? instance.getValue() : null;
	}

	private static <K, V> void put(final Map<K, V> instance, final K key, final V value) {
		if (instance != null) {
			instance.put(key, value);
		}
	}

	private static String longestCommonSubstring(final String a, final String b) {
		//
		int start = 0, max = 0;
		//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(stream(testAndApply(Objects::nonNull, getClass(a), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), VALUE)), Collectors.toList()),
				x -> get(x, 0), null);
		//
		final boolean conditionA = or(field, Objects::isNull, f -> Narcissus.getField(a, f) != null);
		//
		final boolean conditionB = or(field, Objects::isNull,
				f -> and(b, Objects::nonNull, g -> Narcissus.getField(g, f) != null));
		//
		for (int i = 0; and(conditionA, (value, index) -> index < StringUtils.length(value), a, i); i++) {
			//
			for (int j = 0; and(conditionB, (value, index) -> index < StringUtils.length(value), b, j); j++) {
				//
				int x = 0;
				//
				while (a.charAt(i + x) == b.charAt(j + x)) {
					//
					x++;
					//
					if (((i + x) >= a.length()) || ((j + x) >= b.length())) {
						//
						break;
						//
					} // if
						//
				} // while
					//
				if (x > max) {
					//
					max = x;
					//
					start = i;
					//
				} // if
					//
			} // for
				//
		} // for
			//
		return conditionA ? StringUtils.substring(a, start, start + max) : null;
		//
	}

	private static <T> boolean and(final boolean condition, final ObjIntPredicate<T> objIntPredicate, final T value,
			final int integer) {
		return condition && objIntPredicate != null && objIntPredicate.test(value, integer);
	}

	private static <T> boolean and(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) && test(b, value);
	}

	private static <T> boolean or(final T value, final Predicate<T> a, final Predicate<T> b) {
		return test(a, value) || test(b, value);
	}

	private static int size(final Collection<?> instance) {
		return instance != null ? instance.size() : 0;
	}

	private static <E> E get(final List<E> instance, final int index) {
		return instance != null ? instance.get(index) : null;
	}

	private static String getName(final X500Principal instance) {
		//
		if (instance == null) {
			//
			return null;
			//
		} // if
			//
		final Field field = testAndApply(x -> size(x) == 1,
				collect(filter(
						stream(testAndApply(Objects::nonNull, getClass(instance), FieldUtils::getAllFieldsList, null)),
						f -> Objects.equals(getName(f), "thisX500Name")), Collectors.toList()),
				x -> get(x, 0), null);
		//
		return field == null || Narcissus.getField(instance, field) != null ? instance.getName() : null;
		//
	}

	private static String getName(final Member instance) {
		return instance != null ? instance.getName() : null;
	}

	private static <T, R, A> R collect(final Stream<T> instance, final Collector<? super T, A, R> collector) {
		//
		return instance != null && (collector != null || Proxy.isProxyClass(getClass(instance)))
				? instance.collect(collector)
				: null;
		//
	}

	private static <T> Stream<T> filter(final Stream<T> instance, final Predicate<? super T> predicate) {
		return instance != null ? instance.filter(predicate) : instance;
	}

	private static <T> Stream<T> stream(final Collection<T> instance) {
		return instance != null ? instance.stream() : null;
	}

	private static Class<?> getClass(final Object instance) {
		return instance != null ? instance.getClass() : null;
	}

	private static <T, R, E extends Throwable> R testAndApply(final Predicate<T> predicate, final T value,
			final FailableFunction<T, R, E> functionTrue, final FailableFunction<T, R, E> functionFalse) throws E {
		return test(predicate, value) ? apply(functionTrue, value) : apply(functionFalse, value);
	}

	private static <T> boolean test(final Predicate<T> instance, final T value) {
		return instance != null && instance.test(value);
	}

	private static <T, R, E extends Throwable> R apply(final FailableFunction<T, R, E> instance, final T value)
			throws E {
		return instance != null ? instance.apply(value) : null;
	}

}