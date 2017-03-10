package com.emp.config;


import java.util.Properties;

import javax.persistence.EntityManager;
import javax.persistence.EntityManagerFactory;
import javax.sql.DataSource;

import org.apache.commons.dbcp.BasicDataSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.env.Environment;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.instrument.classloading.InstrumentationLoadTimeWeaver;
import org.springframework.jdbc.datasource.lookup.JndiDataSourceLookup;
import org.springframework.orm.jpa.JpaTransactionManager;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import org.springframework.orm.jpa.vendor.HibernateJpaVendorAdapter;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.EnableTransactionManagement;

@Configuration
@EnableTransactionManagement
@EnableJpaRepositories(entityManagerFactoryRef = "entityManagerFactory", transactionManagerRef = "empTransactionManager", basePackages = { "com.anuraj.repositories" })
public class EmpPersistenceConfig {

	@Autowired
	private Environment env;

	@Profile("dev")
	@Bean(name = "empDataSource")
	public DataSource dataSourceDev() {
		BasicDataSource dataSource = new BasicDataSource();
/*
		InputStream inputStream = null;

		try {
			Properties prop = new Properties();
		String strFileName = "env-dev.properties";
		inputStream = getClass().getClassLoader().getResourceAsStream(
				strFileName);

		if (inputStream != null) {
			prop.load(inputStream);
		} else {
			throw new FileNotFoundException("property file " + strFileName
					+ " not found ");
		}

		dataSource.setDriverClassName(prop
				.getProperty("emp.datasource.driverClassName"));
		dataSource.setUrl(prop.getProperty("emp.datasource.url"));
		dataSource.setUsername(prop.getProperty("emp.datasource.username"));
		dataSource.setPassword(prop.getProperty("emp.datasource.password"));


		}catch (Exception ex) {
			return null;
		} finally {
			try {
				inputStream.close();
			} catch (Exception ex) {
				// TODO
			}
		}*/

		dataSource.setDriverClassName(env
				.getProperty("emp.datasource.driverClassName"));
		dataSource.setUrl(env.getProperty("emp.datasource.url"));
		dataSource.setUsername(env.getProperty("emp.datasource.username"));
		dataSource.setPassword(env.getProperty("emp.datasource.password"));

		return dataSource;
	}

	@Bean(name = "empDataSource")
	@Profile("production")
	public DataSource dataSource() {
		JndiDataSourceLookup dataSourceLookup = new JndiDataSourceLookup();
		return dataSourceLookup.getDataSource("java:comp/env/jdbc/emp");
	}

	@Bean(name = "empEntityManager")
	public EntityManager entityManager() {
		return entityManagerFactory().createEntityManager();
	}

	@Bean
	public EntityManagerFactory entityManagerFactory() {
		LocalContainerEntityManagerFactoryBean factory = new LocalContainerEntityManagerFactoryBean();
		HibernateJpaVendorAdapter vendorAdapter = new HibernateJpaVendorAdapter();
		vendorAdapter.setGenerateDdl(Boolean.FALSE);
		vendorAdapter.setShowSql(Boolean.FALSE);
		factory.setDataSource(dataSource());
		factory.setJpaVendorAdapter(vendorAdapter);
		factory.setPackagesToScan("com.anuraj.entity");
		Properties jpaProperties = new Properties();
		jpaProperties.put("hibernate.dialect",
				env.getProperty("spring.jpa.properties.hibernate.dialect"));
		factory.setJpaProperties(jpaProperties);
		factory.setPersistenceUnitName("empPersistenceUnit");
		factory.afterPropertiesSet();
		factory.setLoadTimeWeaver(new InstrumentationLoadTimeWeaver());
		return factory.getObject();
	}

	@Bean(name = "empTransactionManager")
	public PlatformTransactionManager transactionManager() {
		EntityManagerFactory factory = entityManagerFactory();
		return new JpaTransactionManager(factory);
	}
	

}
