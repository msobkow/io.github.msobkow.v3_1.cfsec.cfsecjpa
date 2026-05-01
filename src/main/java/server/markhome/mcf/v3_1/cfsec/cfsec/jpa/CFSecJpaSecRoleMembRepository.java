// Description: Java 25 Spring JPA Repository for SecRoleMemb

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
 *	JpaRepository for the CFSecJpaSecRoleMemb entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecRoleMembRepository extends JpaRepository<CFSecJpaSecRoleMemb, CFSecJpaSecRoleMembPKey> {

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecRoleMemb r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId and r.pkey.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecRoleMemb get(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecRoleMembPKey based read method for object-based access.
	 *
	 *		@param key The key of the entity to be read.
	 *
	 *		@return The entity read, usually from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecRoleMemb get(ICFSecSecRoleMembPKey key) {
		return( get(key.getRequiredSecRoleId(), key.getRequiredLoginId()));
	}

	// CFSecJpaSecRoleMemb specified index readers

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecRoleMembByRoleIdxKey as arguments.
	 *
	 *		@param requiredSecRoleId
	 *
	 *		@return List&lt;CFSecJpaSecRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecRoleMemb r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId")
	List<CFSecJpaSecRoleMemb> findByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId);

	/**
	 *	CFSecSecRoleMembByRoleIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecRoleMembByRoleIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecRoleMemb> findByRoleIdx(ICFSecSecRoleMembByRoleIdxKey key) {
		return( findByRoleIdx(key.getRequiredSecRoleId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecRoleMembByLoginIdxKey as arguments.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return List&lt;CFSecJpaSecRoleMemb&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecRoleMemb r where r.pkey.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecRoleMemb> findByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecRoleMembByLoginIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecRoleMembByLoginIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecRoleMemb> findByLoginIdx(ICFSecSecRoleMembByLoginIdxKey key) {
		return( findByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredLoginId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecRoleMemb r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId and r.pkey.requiredParentUser.requiredLoginId = :loginId")
	CFSecJpaSecRoleMemb lockByIdIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecRoleMemb lockByIdIdx(ICFSecSecRoleMembPKey key) {
		return( lockByIdIdx(key.getRequiredSecRoleId(), key.getRequiredLoginId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecRoleMemb r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId")
	List<CFSecJpaSecRoleMemb> lockByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId);

	/**
	 *	CFSecSecRoleMembByRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecRoleMemb> lockByRoleIdx(ICFSecSecRoleMembByRoleIdxKey key) {
		return( lockByRoleIdx(key.getRequiredSecRoleId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecRoleMemb r where r.pkey.requiredParentUser.requiredLoginId = :loginId")
	List<CFSecJpaSecRoleMemb> lockByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecRoleMemb> lockByLoginIdx(ICFSecSecRoleMembByLoginIdxKey key) {
		return( lockByLoginIdx(key.getRequiredLoginId()));
	}

	// CFSecJpaSecRoleMemb specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecRoleMemb r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId and r.pkey.requiredParentUser.requiredLoginId = :loginId")
	void deleteByIdIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId,
		@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecRoleMembByIdIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecRoleMembByIdIdxKey of the entity to be locked.
	 */
	default void deleteByIdIdx(ICFSecSecRoleMembPKey key) {
		deleteByIdIdx(key.getRequiredSecRoleId(), key.getRequiredLoginId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecRoleId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecRoleMemb r where r.pkey.requiredContainerRole.requiredSecRoleId = :secRoleId")
	void deleteByRoleIdx(@Param("secRoleId") CFLibDbKeyHash256 requiredSecRoleId);

	/**
	 *	CFSecSecRoleMembByRoleIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecRoleMembByRoleIdxKey of the entity to be locked.
	 */
	default void deleteByRoleIdx(ICFSecSecRoleMembByRoleIdxKey key) {
		deleteByRoleIdx(key.getRequiredSecRoleId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecRoleMemb r where r.pkey.requiredParentUser.requiredLoginId = :loginId")
	void deleteByLoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecRoleMembByLoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecRoleMembByLoginIdxKey of the entity to be locked.
	 */
	default void deleteByLoginIdx(ICFSecSecRoleMembByLoginIdxKey key) {
		deleteByLoginIdx(key.getRequiredLoginId());
	}

}
