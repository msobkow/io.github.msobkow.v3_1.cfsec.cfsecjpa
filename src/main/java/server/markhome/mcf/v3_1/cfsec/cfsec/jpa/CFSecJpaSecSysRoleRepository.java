// Description: Java 25 Spring JPA Repository for SecSysRole

/*
 *	server.markhome.mcf.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow mark.sobkow@gmail.com
 *	
 *	These files are part of Mark's Code Fractal CFSec.
 *	
 *	Licensed under the Apache License, Version 2.0 (the "License");
 *	you may not use this file except in compliance with the License.
 *	You may obtain a copy of the License at
 *	
 *	http://www.apache.org/licenses/LICENSE-2.0
 *	
 *	Unless required by applicable law or agreed to in writing, software
 *	distributed under the License is distributed on an "AS IS" BASIS,
 *	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *	See the License for the specific language governing permissions and
 *	limitations under the License.
 *	
 */

package server.markhome.mcf.v3_1.cfsec.cfsec.jpa;

import java.io.Serializable;
import java.math.*;
import java.time.*;
import java.util.*;
import jakarta.persistence.*;
import server.markhome.mcf.v3_1.cflib.*;
import server.markhome.mcf.v3_1.cflib.dbutil.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.transaction.annotation.Transactional;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	JpaRepository for the CFSecJpaSecSysRole entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecSysRoleRepository extends JpaRepository<CFSecJpaSecSysRole, ICFLibKeyHash256> {

	@Transactional
	@Modifying
	CFSecJpaSecSysRole save(CFSecJpaSecSysRole obj);

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecSysRole r where r.requiredSecSysRoleId = :secSysRoleId")
	CFSecJpaSecSysRole get(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId);

	// CFSecJpaSecSysRole specified index readers

	/**
	 *	Read an entity using the columns of the CFSecSecSysRoleByUNameIdxKey as arguments.
	 *
	 *		@param requiredName
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecSysRole r where r.requiredName = :name")
	CFSecJpaSecSysRole findByUNameIdx(@Param("name") String requiredName);

	/**
	 *	CFSecSecSysRoleByUNameIdxKey entity reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleByUNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecSysRole findByUNameIdx(ICFSecSecSysRoleByUNameIdxKey key) {
		return( findByUNameIdx(key.getRequiredName()));
	}

	// CFSecJpaSecSysRole specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRole r where r.requiredSecSysRoleId = :secSysRoleId")
	CFSecJpaSecSysRole lockByIdIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId);

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecSysRole r where r.requiredName = :name")
	CFSecJpaSecSysRole lockByUNameIdx(@Param("name") String requiredName);

	/**
	 *	CFSecSecSysRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecSysRole lockByUNameIdx(ICFSecSecSysRoleByUNameIdxKey key) {
		return( lockByUNameIdx(key.getRequiredName()));
	}

	// CFSecJpaSecSysRole specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecSysRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRole r where r.requiredSecSysRoleId = :secSysRoleId")
	void deleteByIdIdx(@Param("secSysRoleId") ICFLibKeyHash256 requiredSecSysRoleId);

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecSysRole r where r.requiredName = :name")
	void deleteByUNameIdx(@Param("name") String requiredName);

	/**
	 *	CFSecSecSysRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecSysRoleByUNameIdxKey of the entity to be locked.
	 */
	default void deleteByUNameIdx(ICFSecSecSysRoleByUNameIdxKey key) {
		deleteByUNameIdx(key.getRequiredName());
	}

}
