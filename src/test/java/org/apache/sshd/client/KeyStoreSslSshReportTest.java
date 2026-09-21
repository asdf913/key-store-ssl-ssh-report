package org.apache.sshd.client;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Array;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Member;
import java.lang.reflect.Method;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Objects;
import java.util.Optional;
import java.util.Properties;
import java.util.function.BiPredicate;
import java.util.function.Predicate;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.net.ssl.HttpsURLConnection;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathFactory;

import org.apache.commons.lang3.ArrayUtils;
import org.apache.commons.lang3.ObjectUtils;
import org.apache.commons.lang3.function.FailableBiConsumer;
import org.apache.commons.lang3.function.FailableBiFunction;
import org.apache.commons.lang3.function.FailableFunction;
import org.apache.commons.lang3.function.FailableRunnable;
import org.apache.commons.lang3.reflect.FieldUtils;
import org.apache.commons.validator.routines.DomainValidator;
import org.apache.sshd.client.future.AuthFuture;
import org.apache.sshd.client.session.ClientSession;
import org.apache.sshd.client.session.ClientSessionCreator;
import org.apache.sshd.common.auth.BasicCredentialsProvider;
import org.apache.sshd.common.auth.PasswordHolder;
import org.apache.sshd.common.auth.UsernameHolder;
import org.apache.sshd.common.config.keys.loader.KeyPairResourceLoader;
import org.apache.sshd.common.file.virtualfs.VirtualFileSystemFactory;
import org.apache.sshd.common.future.VerifiableFuture;
import org.apache.sshd.common.session.SessionHolder;
import org.apache.sshd.server.SshServer;
import org.apache.sshd.server.keyprovider.SimpleGeneratorHostKeyProvider;
import org.apache.sshd.server.shell.ProcessShellCommandFactory;
import org.apache.sshd.server.shell.ProcessShellFactory;
import org.apache.sshd.sftp.client.SftpClientFactory;
import org.apache.sshd.sftp.server.SftpSubsystemFactory;
import org.d2ab.function.ObjIntPredicate;
import org.slf4j.Logger;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.w3c.dom.DOMException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import com.google.common.net.HostAndPort;
import com.google.common.reflect.Reflection;

import io.github.toolfactory.narcissus.Narcissus;

public class KeyStoreSslSshReportTest {

	private static Method METHOD_GET_NAME, METHOD_GET_CERTIFICATE, METHOD_LOAD, METHOD_IS_KEY_ENTRY,
			METHOD_IS_CERTIFICATE_ENTRY, METHOD_IS_VALID, METHOD_FORMAT, METHOD_TO_CHAR_ARRAY,
			METHOD_LONGEST_COMMON_SUB_STRING, METHOD_SUBSTRACT, METHOD_INFO2, METHOD_INFO3, METHOD_NEW_DOCUMENT_BUILDER,
			METHOD_TEST_AND_RUN, METHOD_TEST_AND_APPLY, METHOD_FILTER, METHOD_COLLECT, METHOD_TO_PATH, METHOD_IS_FILE,
			METHOD_TEST_AND_ACCEPT, METHOD_PERFORM, METHOD_CAST, METHOD_NEW_XPATH, METHOD_EVALUATE = null;

	private static Class<?> CLASS_RESULT = null;

	@BeforeClass
	static void beforeClass() throws Throwable {
		//
		final Class<?> clz = KeyStoreSslSshReport.class;
		//
		(METHOD_GET_NAME = clz.getDeclaredMethod("getName", Member.class)).setAccessible(true);
		//
		(METHOD_GET_CERTIFICATE = clz.getDeclaredMethod("getCertificate", KeyStore.class, String.class))
				.setAccessible(true);
		//
		(METHOD_LOAD = clz.getDeclaredMethod("load", KeyStore.class, InputStream.class, char[].class))
				.setAccessible(true);
		//
		(METHOD_IS_KEY_ENTRY = clz.getDeclaredMethod("isKeyEntry", KeyStore.class, String.class)).setAccessible(true);
		//
		(METHOD_IS_CERTIFICATE_ENTRY = clz.getDeclaredMethod("isCertificateEntry", KeyStore.class, String.class))
				.setAccessible(true);
		//
		(METHOD_IS_VALID = clz.getDeclaredMethod("isValid", DomainValidator.class, String.class)).setAccessible(true);
		//
		(METHOD_FORMAT = clz.getDeclaredMethod("format", DateFormat.class, Date.class)).setAccessible(true);
		//
		(METHOD_TO_CHAR_ARRAY = clz.getDeclaredMethod("toCharArray", String.class)).setAccessible(true);
		//
		(METHOD_LONGEST_COMMON_SUB_STRING = clz.getDeclaredMethod("longestCommonSubstring", String.class, String.class))
				.setAccessible(true);
		//
		(METHOD_SUBSTRACT = clz.getDeclaredMethod("substract", Date.class, Date.class)).setAccessible(true);
		//
		(METHOD_TEST_AND_APPLY = clz.getDeclaredMethod("testAndApply", Predicate.class, Object.class,
				FailableFunction.class, FailableFunction.class)).setAccessible(true);
		//
		(METHOD_FILTER = clz.getDeclaredMethod("filter", Stream.class, Predicate.class)).setAccessible(true);
		//
		(METHOD_COLLECT = clz.getDeclaredMethod("collect", Stream.class, Collector.class)).setAccessible(true);
		//
		(METHOD_TEST_AND_RUN = clz.getDeclaredMethod("testAndRun", Boolean.TYPE, FailableRunnable.class))
				.setAccessible(true);
		//
		(METHOD_TO_PATH = clz.getDeclaredMethod("toPath", File.class)).setAccessible(true);
		//
		(METHOD_IS_FILE = clz.getDeclaredMethod("isFile", File.class)).setAccessible(true);
		//
		(METHOD_TEST_AND_ACCEPT = clz.getDeclaredMethod("testAndAccept", BiPredicate.class, Object.class, Object.class,
				FailableBiConsumer.class)).setAccessible(true);
		//
		(METHOD_NEW_DOCUMENT_BUILDER = clz.getDeclaredMethod("newDocumentBuilder", DocumentBuilderFactory.class))
				.setAccessible(true);
		//
		(METHOD_PERFORM = clz.getDeclaredMethod("perform", Document.class, XPath.class)).setAccessible(true);
		//
		(METHOD_CAST = clz.getDeclaredMethod("cast", Class.class, Object.class)).setAccessible(true);
		//
		(METHOD_NEW_XPATH = clz.getDeclaredMethod("newXPath", XPathFactory.class)).setAccessible(true);
		//
		(METHOD_EVALUATE = clz.getDeclaredMethod("evaluate", XPath.class, String.class, Object.class))
				.setAccessible(true);
		//
		(METHOD_INFO2 = clz.getDeclaredMethod("info", Logger.class,
				CLASS_RESULT = testAndApply(x -> x != null && x.size() == 1,
						collect(filter(Arrays.stream(clz.getDeclaredClasses()),
								f -> Objects.equals(f != null ? f.getSimpleName() : null, "Result")),
								Collectors.toList()),
						x -> x != null ? x.get(0) : null, null)))
				.setAccessible(true);
		//
	}

	private static <T, R, A> R collect(final Stream<T> instance, final Collector<? super T, A, R> collector)
			throws Throwable {
		try {
			return (R) invoke(METHOD_COLLECT, null, instance, collector);
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	private static <T> Stream<T> filter(final Stream<T> instance, final Predicate<? super T> predicate)
			throws Throwable {
		try {
			final Object obj = invoke(METHOD_FILTER, null, instance, predicate);
			if (obj == null) {
				return null;
			} else if (obj instanceof Stream) {
				return (Stream) obj;
			}
			throw new Throwable(Objects.toString(getClass(instance)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	private static <T, R, E extends Throwable> R testAndApply(final Predicate<T> predicate, final T value,
			final FailableFunction<T, R, E> functionTrue, final FailableFunction<T, R, E> functionFalse)
			throws Throwable {
		try {
			return (R) invoke(METHOD_TEST_AND_APPLY, null, predicate, value, functionTrue, functionFalse);
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	private static class IH implements InvocationHandler {

		private Boolean test, containsKey, hasMoreElements, add, anyMatch, isSuccess;

		private Integer size, length;

		@Override
		public Object invoke(final Object proxy, final Method method, final Object[] args) throws Throwable {
			//
			final String name = getName(method);
			//
			if (Objects.equals(method != null ? method.getReturnType() : null, Void.TYPE)) {
				//
				return null;
				//
			} // if
				//
			if (proxy instanceof Collection) {
				//
				if (Objects.equals(name, "size")) {
					//
					return size;
					//
				} else if (Objects.equals(name, "stream")) {
					//
					return null;
					//
				} else if (Objects.equals(name, "add")) {
					//
					return add;
					//
				} // if
					//
			} // if
				//
			if (proxy instanceof Map) {
				//
				if (Objects.equals(name, "containsKey")) {
					//
					return containsKey;
					//
				} else if (contains(Arrays.asList("get", "put", "entrySet", "keySet"), name)) {
					//
					return null;
					//
				} // if
					//
			} else if (or(proxy instanceof Predicate, proxy instanceof ObjIntPredicate, proxy instanceof BiPredicate)
					&& Objects.equals(name, "test")) {
				//
				return test;
				//
			} else if (Boolean.logicalOr(proxy instanceof FailableFunction, proxy instanceof FailableBiFunction)
					&& Objects.equals(name, "apply")) {
				//
				return null;
				//
			} else if (proxy instanceof Stream) {
				//
				if (contains(Arrays.asList("collect", "filter", "max"), name)) {
					//
					return null;
					//
				} else if (Objects.equals(name, "anyMatch")) {
					//
					return anyMatch;
					//
				} // if
					//
			} else if (proxy instanceof List && Objects.equals(name, "get")) {
				//
				return null;
				//
			} else if (proxy instanceof Member && Objects.equals(name, "getName")) {
				//
				return null;
				//
			} else if (proxy instanceof Entry && contains(Arrays.asList("getValue", "getKey"), name)) {
				//
				return null;
				//
			} else if (proxy instanceof Enumeration) {
				//
				if (Objects.equals(name, "hasMoreElements")) {
					//
					return hasMoreElements;
					//
				} else if (Objects.equals(name, "nextElement")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof XPath && Objects.equals(name, "evaluate")) {
				//
				return null;
				//
			} else if (proxy instanceof Node && Objects.equals(name, "getTextContent")) {
				//
				return null;
				//
			} else if (proxy instanceof NodeList) {
				//
				if (Objects.equals(name, "getLength")) {
					//
					return length;
					//
				} else if (Objects.equals(name, "item")) {
					//
					return null;
					//
				} // if
					//
			} else if (proxy instanceof VerifiableFuture && Objects.equals(name, "verify")) {
				//
				return null;
				//
			} else if (proxy instanceof SessionHolder && Objects.equals(name, "getSession")) {
				//
				return null;
				//
			} else if (proxy instanceof AuthFuture && Objects.equals(name, "isSuccess")) {
				//
				return isSuccess;
				//
			} else if (proxy instanceof ClientSession && Objects.equals(name, "auth")) {
				//
				return null;
				//
			} else if (proxy instanceof ClientSessionCreator && Objects.equals(name, "connect")) {
				//
				return null;
				//
			} else if (proxy instanceof SftpClientFactory && Objects.equals(name, "createSftpFileSystem")) {
				//
				return null;
				//
			} else if (proxy instanceof KeyPairResourceLoader && Objects.equals(name, "loadKeyPairs")) {
				//
				return null;
				//
			} else if (proxy instanceof UsernameHolder && Objects.equals(name, "getUsername")) {
				//
				return null;
				//
			} else if (proxy instanceof PasswordHolder && Objects.equals(name, "getPassword")) {
				//
				return null;
				//
			} // if
				//
			throw new Throwable(name);
			//
		}

		private static boolean or(final boolean a, final boolean b, final boolean c) {
			//
			boolean result = a || b;
			//
			if (result) {
				//
				return result;
				//
			} // if
				//
			return result || c;
			//
		}

	}

	private KeyStore keyStore = null;

	private SshServer sshServer = null;

	private IH ih = null;

	@BeforeMethod
	void beforeMethod() throws IllegalAccessException, InvocationTargetException, KeyStoreException, IOException {
		//
		Assert.assertNull(
				invoke(METHOD_LOAD, null, keyStore = KeyStore.getInstance(KeyStore.getDefaultType()), null, null));
		//
		if ((sshServer = SshServer.setUpDefaultServer()) != null) {
			//
			sshServer.setHost("127.0.0.1");
			//
			sshServer.setPort(2222);
			//
			sshServer.setKeyPairProvider(new SimpleGeneratorHostKeyProvider());
			//
			sshServer.setPasswordAuthenticator((username, password, session) -> Objects.equals(username, "user")
					&& Objects.equals(password, "password"));
			//
			sshServer.setCommandFactory(new ProcessShellCommandFactory());
			//
			final String name = getName(getClass(FileSystems.getDefault()));
			//
			if (contains(Arrays.asList("sun.nio.fs.MacOSXFileSystem", "sun.nio.fs.LinuxFileSystem"), name)) {
				//
				sshServer.setShellFactory(new ProcessShellFactory("/bin/sh", "-i"));
				//
			} else {
				//
				throw new IllegalStateException(name);
				//
			} // if
				//
			sshServer.setSubsystemFactories(Collections.singletonList(new SftpSubsystemFactory()));
			//
			sshServer.setFileSystemFactory(new VirtualFileSystemFactory(Paths.get("/")));
			//
			sshServer.start();
			//
		} // if
			//
		ih = new IH();
		//
	}

	@AfterMethod
	void afterMethod() throws IOException {
		//
		if (sshServer != null) {
			//
			sshServer.close();
			//
		} // if
			//
	}

	private static String getName(final Class<?> instance) {
		return instance != null ? instance.getName() : null;
	}

	private static boolean contains(final Collection<?> instance, final Object item) {
		return instance != null && instance.contains(item);
	}

	private static String getName(final Member instance) throws Throwable {
		try {
			final Object obj = invoke(METHOD_GET_NAME, null, instance);
			if (obj == null) {
				return null;
			} else if (obj instanceof String) {
				return (String) obj;
			}
			throw new Throwable(Objects.toString(getClass(instance)));
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test

	public void testNull() throws Throwable {
		//
		final Method[] ms = KeyStoreSslSshReport.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType = null;
		//
		Object result = null;
		//
		String toString, name = null;
		//
		Collection<Object> collection = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if (Objects.equals(parameterType = ArrayUtils.get(parameterTypes, j), Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Long.TYPE)) {
					//
					add(collection, Long.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.TRUE);
					//
				} else {
					//
					add(collection, null);
					//
				} // if
					//
			} // for
				//
			result = Narcissus.invokeStaticMethod(m, toArray(collection));
			//
			toString = Objects.toString(m);
			//
			if (contains(Arrays.asList(Boolean.TYPE, Integer.TYPE, Long.TYPE), m.getReturnType())
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getEntry"),
							Arrays.equals(parameterTypes, new Class<?>[] { String.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "perform"), Arrays.equals(parameterTypes,
							new Class<?>[] { KeyStore.class, String.class })
							|| Arrays.equals(parameterTypes, new Class<?>[] { String.class, Map.class, Map.class })
							|| Arrays.equals(parameterTypes,
									new Class<?>[] { HostAndPort.class, Map.class, BasicCredentialsProvider.class,
											File.class, String.class, char[].class, String.class, Map.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "validate"),
							Arrays.equals(parameterTypes, new Class<?>[] { File.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "readByteArray"),
							Arrays.equals(parameterTypes, new Class<?>[] { HostAndPort.class,
									BasicCredentialsProvider.class, File.class, String.class }))) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//

	}

	private static <E> void add(final Collection<E> instance, final E item) {
		if (instance != null) {
			instance.add(item);
		}
	}

	private static void clear(final Collection<?> instance) {
		if (instance != null) {
			instance.clear();
		}
	}

	private static Object[] toArray(final Collection<?> instance) {
		return instance != null ? instance.toArray() : null;
	}

	@Test
	void testNotNull() throws Throwable {
		//
		final Method[] ms = KeyStoreSslSshReport.class.getDeclaredMethods();
		//
		Method m = null;
		//
		Class<?>[] parameterTypes = null;
		//
		Class<?> parameterType = null;
		//
		Object result = null;
		//
		String toString, name = null;
		//
		Collection<Object> collection = null;
		//
		for (int i = 0; ms != null && i < ms.length; i++) {
			//
			if ((m = ArrayUtils.get(ms, i)) == null || m.isSynthetic()
					|| (parameterTypes = m.getParameterTypes()) == null) {
				//
				continue;
				//
			} // if
				//
			clear(collection = ObjectUtils.getIfNull(collection, ArrayList::new));
			//
			for (int j = 0; j < parameterTypes.length; j++) {
				//
				if ((parameterType = ArrayUtils.get(parameterTypes, j)) != null && parameterType.isInterface()) {
					//
					if ((ih = ObjectUtils.getIfNull(ih, IH::new)) != null) {
						//
						final List<Field> fs = FieldUtils.getAllFieldsList(getClass(ih));
						//
						Field f = null;
						//
						for (int k = 0; fs != null && k < fs.size(); k++) {
							//
							if ((f = fs.get(k)) == null) {
								//
								continue;
								//
							} // if
								//
							final Class<?> type = f.getType();
							//
							if (Objects.equals(type, Boolean.class)) {
								//
								Narcissus.setField(ih, f, Boolean.TRUE);
								//
							} else if (Objects.equals(type, Integer.class)) {
								//
								Narcissus.setField(ih, f, Integer.valueOf(0));
								//
							} // if
								//
						} // for
							//
					} // if
						//
					add(collection, Reflection.newProxy(parameterType, ih = ObjectUtils.getIfNull(ih, IH::new)));
					//
				} else if (parameterType != null && parameterType.isArray()) {
					//
					add(collection, Array.newInstance(parameterType.getComponentType(), 0));
					//
				} else if (Objects.equals(parameterType, DateFormat.class)) {
					//
					add(collection, Narcissus.allocateInstance(SimpleDateFormat.class));
					//
				} else if (Objects.equals(parameterType, Integer.TYPE)) {
					//
					add(collection, Integer.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Long.TYPE)) {
					//
					add(collection, Long.valueOf(0));
					//
				} else if (Objects.equals(parameterType, Boolean.TYPE)) {
					//
					add(collection, Boolean.TRUE);
					//
				} else if (Objects.equals(parameterType, KeyStore.class)) {
					//
					add(collection,
							Narcissus.allocateInstance(getClass(KeyStore.getInstance(KeyStore.getDefaultType()))));
					//
				} else if (Objects.equals(parameterType, InputStream.class)) {
					//
					add(collection, Narcissus.allocateInstance(ByteArrayInputStream.class));
					//
				} else if (Objects.equals(parameterType, OutputStream.class)) {
					//
					add(collection, Narcissus.allocateInstance(ByteArrayOutputStream.class));
					//
				} else if (Objects.equals(parameterType, Class.class)) {
					//
					add(collection, Class.class);
					//
				} else if (Objects.equals(parameterType, HttpsURLConnection.class)) {
					//
					add(collection, Narcissus
							.allocateInstance(Class.forName("sun.net.www.protocol.https.HttpsURLConnectionImpl")));
					//
				} else if (Objects.equals(parameterType, X509Certificate.class)) {
					//
					add(collection, Narcissus.allocateInstance(Class.forName("sun.security.x509.X509CertImpl")));
					//
				} else if (Objects.equals(parameterType, DocumentBuilderFactory.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(DocumentBuilderFactory.newInstance())));
					//
				} else if (Objects.equals(parameterType, XPathFactory.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(XPathFactory.newInstance())));
					//
				} else if (Objects.equals(parameterType, DocumentBuilder.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(Narcissus
							.invokeStaticMethod(METHOD_NEW_DOCUMENT_BUILDER, DocumentBuilderFactory.newInstance()))));
					//
				} else if (Objects.equals(parameterType, FileSystem.class)) {
					//
					add(collection, Narcissus.allocateInstance(getClass(FileSystems.getDefault())));
					//
				} else if (Objects.equals(parameterType, Number.class)) {
					//
					add(collection, Narcissus.allocateInstance(Long.class));
					//
				} else {
					//
					add(collection, Narcissus.allocateInstance(parameterType));
					//
				} // if
					//
			} // for
				//
			result = Narcissus.invokeStaticMethod(m, toArray(collection));
			//
			toString = Objects.toString(m);
			//
			if (contains(Arrays.asList(Boolean.TYPE, Integer.TYPE, Long.TYPE), m.getReturnType())
					|| Boolean.logicalAnd(Objects.equals(name = getName(m), "getClass"),
							Arrays.equals(parameterTypes, new Class<?>[] { Object.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "orElse"),
							Arrays.equals(parameterTypes, new Class<?>[] { Optional.class, Object.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "getEntry"),
							Arrays.equals(parameterTypes, new Class<?>[] { String.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "substract"),
							Arrays.equals(parameterTypes, new Class<?>[] { Date.class, Date.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "perform"), Arrays.equals(parameterTypes,
							new Class<?>[] { KeyStore.class, String.class })
							|| Arrays.equals(parameterTypes, new Class<?>[] { String.class, Map.class, Map.class })
							|| Arrays.equals(parameterTypes,
									new Class<?>[] { HostAndPort.class, Map.class, BasicCredentialsProvider.class,
											File.class, String.class, char[].class, String.class, Map.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "iif"),
							Arrays.equals(parameterTypes, new Class<?>[] { Boolean.TYPE, Object.class, Object.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "validate"),
							Arrays.equals(parameterTypes, new Class<?>[] { File.class }))
					|| Boolean.logicalAnd(Objects.equals(name, "readByteArray"),
							Arrays.equals(parameterTypes, new Class<?>[] { HostAndPort.class,
									BasicCredentialsProvider.class, File.class, String.class }))) {
				//
				Assert.assertNotNull(result, toString);
				//
			} else {
				//
				Assert.assertNull(result, toString);
				//
			} // if
				//
		} // for
			//
	}

	private static Class<?> getClass(final Object instance) {
		return instance != null ? instance.getClass() : null;
	}

	@Test
	public void testMain() throws Exception {
		//
		KeyStoreSslSshReport.main(new String[] { "config=" });
		//
		KeyStoreSslSshReport.main(new String[] { "config= " });
		//
		KeyStoreSslSshReport.main(new String[] { "config=." });
		//
		KeyStoreSslSshReport.main(new String[] { "config=pom.xml" });
		//
		final String host = "127.0.0.1";
		//
		final String user = "user";
		//
		KeyStoreSslSshReport
				.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password", "file=" });
		//
		KeyStoreSslSshReport.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password",
				"file= ", "keyPath=" });
		//
		KeyStoreSslSshReport.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password",
				"file= ", "keyPath= " });
		//
		KeyStoreSslSshReport.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password",
				"file= ", "keyPath=." });
		//
		KeyStoreSslSshReport.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password",
				"file= ", "keyPath=1" });
		//
		final File file = new File("/etc/ssl/certs/java/cacerts");
		//
		if (file.exists()) {
			//
			final Properties properties = System.getProperties();
			//
			KeyStoreSslSshReport.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password",
					"file=" + file.getAbsolutePath() });
			//
			if (properties != null && properties.containsKey("url")) {
				//
				KeyStoreSslSshReport
						.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password",
								"file=" + file.getAbsolutePath(), "url=" + properties.getProperty("url") });
				//
			} // if
				//
		} else {
			//
			KeyStoreSslSshReport
					.main(new String[] { "host=" + host, "port=2222", "user=" + user, "password=password" });
			//
		} // if
			//
	}

	private static Object invoke(final Method method, final Object instance, final Object... args)
			throws IllegalAccessException, InvocationTargetException {
		return method != null && method.getDeclaringClass() != null ? method.invoke(instance, args) : null;
	}

	@Test
	public void testGetCertificate() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNull(invoke(METHOD_GET_CERTIFICATE, null, keyStore, null));
		//
		Assert.assertNull(invoke(METHOD_GET_CERTIFICATE, null, keyStore, ""));
		//
		Assert.assertNull(invoke(METHOD_GET_CERTIFICATE, null, keyStore, Narcissus.allocateInstance(String.class)));
		//
	}

	@Test
	public void testIsKeyEntry() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_IS_KEY_ENTRY, null, keyStore, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_KEY_ENTRY, null, keyStore, ""), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_KEY_ENTRY, null, keyStore, Narcissus.allocateInstance(String.class)),
				Boolean.FALSE);
		//
	}

	@Test
	public void testIsCertificateEntry() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_IS_CERTIFICATE_ENTRY, null, keyStore, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_CERTIFICATE_ENTRY, null, keyStore, ""), Boolean.FALSE);
		//
		Assert.assertEquals(
				invoke(METHOD_IS_CERTIFICATE_ENTRY, null, keyStore, Narcissus.allocateInstance(String.class)),
				Boolean.FALSE);
		//
	}

	@Test
	public void testIsValid() throws IllegalAccessException, InvocationTargetException {
		//
		final DomainValidator domainValidator = DomainValidator.getInstance();
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, null), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, ""), Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, "z.cn"), Boolean.TRUE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, domainValidator, Narcissus.allocateInstance(String.class)),
				Boolean.FALSE);
		//
		Assert.assertEquals(invoke(METHOD_IS_VALID, null, Narcissus.allocateInstance(DomainValidator.class), "z.cn"),
				Boolean.FALSE);
		//
	}

	@Test
	public void testFormat() throws IllegalAccessException, InvocationTargetException, ParseException {
		//
		final DateFormat df = new SimpleDateFormat("yyyy-MM-dd");
		//
		Assert.assertNull(invoke(METHOD_FORMAT, null, df, null));
		//
		final String string = "2001-02-03";
		//
		Assert.assertEquals(invoke(METHOD_FORMAT, null, df, df != null ? df.parse(string) : null), string);
		//
	}

	@Test
	public void testToCharArray() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNotNull(invoke(METHOD_TO_CHAR_ARRAY, null, ""));
		//
	}

	@Test
	public void testSubtract() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNull(invoke(METHOD_SUBSTRACT, null, new Date(), null));
		//
	}

	@Test
	public void testLongestCommonSubstring() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_LONGEST_COMMON_SUB_STRING, null, "abcd", "bcde"), "bcd");
		//
	}

	@Test
	public void testInfo() throws IllegalAccessException, InvocationTargetException, ClassNotFoundException {
		//
		final Object result = Narcissus.allocateInstance(CLASS_RESULT);
		//
		FieldUtils.writeDeclaredField(result, "difference", Long.valueOf(-1), true);
		//
		Assert.assertNull(invoke(METHOD_INFO2, null, null, result));
		//
		FieldUtils.writeDeclaredField(result, "difference", Long.valueOf(1), true);
		//
		Assert.assertNull(invoke(METHOD_INFO2, null, null, result));
		//
		Assert.assertNull(invoke(METHOD_INFO3, null, null, null, Collections.singletonMap(null, null)));
		//
		Assert.assertNull(invoke(METHOD_INFO3, null, null, null, Collections.singletonMap(null,
				Narcissus.allocateInstance(Class.forName("sun.security.x509.X509CertImpl")))));
		//
	}

	@Test
	public void testTestAndRun() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNull(invoke(METHOD_TEST_AND_RUN, null, Boolean.FALSE, null));
		//
	}

	@Test
	public void testToPath() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNotNull(invoke(METHOD_TO_PATH, null, new File(".")));
		//
	}

	@Test
	public void testIsFile() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertEquals(invoke(METHOD_IS_FILE, null, new File("pom.xml")), Boolean.TRUE);
		//
	}

	@Test
	public void testTestAndAccept() throws IllegalAccessException, InvocationTargetException {
		//
		if ((ih = ObjectUtils.getIfNull(ih, IH::new)) != null) {
			//
			ih.test = Boolean.TRUE;
			//
		} // if
			//
		Assert.assertNull(
				invoke(METHOD_TEST_AND_ACCEPT, null, Reflection.newProxy(BiPredicate.class, ih), null, null, null));
		//
	}

	@Test
	public void testPeform() throws Throwable {
		//
		final DocumentBuilder db = cast(DocumentBuilder.class,
				Narcissus.invokeStaticMethod(METHOD_NEW_DOCUMENT_BUILDER, DocumentBuilderFactory.newInstance()));
		//
		final Document document = db != null ? db.newDocument() : null;
		//
		final Node hosts = appendChild(document, createElement(document, "hosts"));
		//
		final Node host = appendChild(hosts, createElement(document, "host"));
		//
		appendChild(host, createElement(document, "ip"));
		//
		appendChild(host, createElement(document, "port"));
		//
		appendChild(host, createElement(document, "user"));
		//
		appendChild(host, createElement(document, "password"));
		//
		Node node = appendChild(host, createElement(document, "urls"));
		//
		appendChild(node, createElement(document, "url"));
		//
		if ((node = appendChild(host, createElement(document, "keyStores"))) != null
				&& (node = appendChild(node, createElement(document, "keyStore"))) != null) {
			//
			appendChild(node, createElement(document, "path"));
			//
		} // if
			//
		Assert.assertNull(
				invoke(METHOD_PERFORM, null, document, invoke(METHOD_NEW_XPATH, null, XPathFactory.newInstance())));
		//
	}

	private static Element createElement(final Document instance, final String tagName) throws DOMException {
		return instance != null ? instance.createElement(tagName) : null;
	}

	private static Node appendChild(final Node instance, final Node newChild) throws DOMException {
		return instance != null ? instance.appendChild(newChild) : null;
	}

	private static <T> T cast(final Class<T> clz, final Object instance) throws Throwable {
		try {
			return (T) invoke(METHOD_CAST, null, clz, instance);
		} catch (final InvocationTargetException e) {
			throw e.getTargetException();
		}
	}

	@Test
	public void testEvaluate() throws IllegalAccessException, InvocationTargetException {
		//
		Assert.assertNull(
				invoke(METHOD_EVALUATE, null, invoke(METHOD_NEW_XPATH, null, XPathFactory.newInstance()), null, null));
		//
	}

}