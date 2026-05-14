// Description: Java 25 Spring JPA Repository for SecUser

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
 *	JpaRepository for the CFSecJpaSecUser entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa.
 *	The manufactured repositories try to provide a rich, do-it-all interface to the JPA data store, with both object and argument-based implementations of the interface defined.
 */
@Transactional(readOnly = true)
public interface CFSecJpaSecUserRepository extends JpaRepository<CFSecJpaSecUser, CFLibDbKeyHash256> {

	/**
	 *	Argument-based get database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecUserId
	 *
	 *		@return The retrieved entity, usually from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecUser r where r.requiredSecUserId = :secUserId")
	CFSecJpaSecUser get(@Param("secUserId") CFLibDbKeyHash256 requiredSecUserId);

	// CFSecJpaSecUser specified index readers

	/**
	 *	Read an entity using the columns of the CFSecSecUserByULoginIdxKey as arguments.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	@Query("select r from CFSecJpaSecUser r where r.requiredLoginId = :loginId")
	CFSecJpaSecUser findByULoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecUserByULoginIdxKey entity reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecUserByULoginIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, typically from the JPA cache, or null if no such entity exists.
	 */
	default CFSecJpaSecUser findByULoginIdx(ICFSecSecUserByULoginIdxKey key) {
		return( findByULoginIdx(key.getRequiredLoginId()));
	}

	/**
	 *	Read zero or more entities into a List using the columns of the CFSecSecUserByEMAddrIdxKey as arguments.
	 *
	 *		@param requiredEMailAddress
	 *
	 *		@return List&lt;CFSecJpaSecUser&gt; of the found entities, typically from the JPA cache, or an empty list if no such entities exist.
	 */
	@Query("select r from CFSecJpaSecUser r where r.requiredEMailAddress = :eMailAddress")
	List<CFSecJpaSecUser> findByEMAddrIdx(@Param("eMailAddress") String requiredEMailAddress);

	/**
	 *	CFSecSecUserByEMAddrIdxKey entity list reader convenience method for object-based access.
	 *
	 *		@param key The CFSecSecUserByEMAddrIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty, typically populated from the JPA cache.
	 */
	default List<CFSecJpaSecUser> findByEMAddrIdx(ICFSecSecUserByEMAddrIdxKey key) {
		return( findByEMAddrIdx(key.getRequiredEMailAddress()));
	}

	// CFSecJpaSecUser specified delete-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecUserId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecUser r where r.requiredSecUserId = :secUserId")
	CFSecJpaSecUser lockByIdIdx(@Param("secUserId") CFLibDbKeyHash256 requiredSecUserId);

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecUser r where r.requiredLoginId = :loginId")
	CFSecJpaSecUser lockByULoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecUserByULoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	default CFSecJpaSecUser lockByULoginIdx(ICFSecSecUserByULoginIdxKey key) {
		return( lockByULoginIdx(key.getRequiredLoginId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEMailAddress
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional
	@Lock(LockModeType.WRITE)
	@Query("select r from CFSecJpaSecUser r where r.requiredEMailAddress = :eMailAddress")
	List<CFSecJpaSecUser> lockByEMAddrIdx(@Param("eMailAddress") String requiredEMailAddress);

	/**
	 *	CFSecSecUserByEMAddrIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	default List<CFSecJpaSecUser> lockByEMAddrIdx(ICFSecSecUserByEMAddrIdxKey key) {
		return( lockByEMAddrIdx(key.getRequiredEMailAddress()));
	}

	// CFSecJpaSecUser specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecUserId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecUser r where r.requiredSecUserId = :secUserId")
	void deleteByIdIdx(@Param("secUserId") CFLibDbKeyHash256 requiredSecUserId);

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredLoginId
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecUser r where r.requiredLoginId = :loginId")
	void deleteByULoginIdx(@Param("loginId") String requiredLoginId);

	/**
	 *	CFSecSecUserByULoginIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecUserByULoginIdxKey of the entity to be locked.
	 */
	default void deleteByULoginIdx(ICFSecSecUserByULoginIdxKey key) {
		deleteByULoginIdx(key.getRequiredLoginId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredEMailAddress
	 */
	@Transactional
	@Modifying
	@Query("delete from CFSecJpaSecUser r where r.requiredEMailAddress = :eMailAddress")
	void deleteByEMAddrIdx(@Param("eMailAddress") String requiredEMailAddress);

	/**
	 *	CFSecSecUserByEMAddrIdxKey based lock method for object-based access.
	 *
	 *		@param key The CFSecSecUserByEMAddrIdxKey of the entity to be locked.
	 */
	default void deleteByEMAddrIdx(ICFSecSecUserByEMAddrIdxKey key) {
		deleteByEMAddrIdx(key.getRequiredEMailAddress());
	}

	/**
	 *	Count system-level security access for permission granted to a specific user by LoginId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmLoginId The LoginId of the user being authorized.
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Query("select count(*) from ("
		+ "select sg0.requiredName as requiredName from CFSecJpaSecSysGrp sg0 join sg0.optionalChildrenMembByGrp mb0 where sg0.requiredName = :parmPermName and mb0.pkey.requiredParentUser.requiredLoginId = :parmLoginId"
		+ " union select sg1.requiredName as requiredName from CFSecJpaSecSysGrp sg1 join sg1.optionalChildrenIncByGrp ig1 join ig1.pkey.requiredParentSubGroup sg1a join sg1a.optionalChildrenMembByGrp mb1 where sg1.requiredName = :parmPermName and mb1.pkey.requiredParentUser.requiredLoginId = :parmLoginId"
		+ " union select sg2.requiredName as requiredName from CFSecJpaSecSysGrp sg2 join sg2.optionalChildrenIncByGrp ig2 join ig2.pkey.requiredParentSubGroup sg2a join sg2a.optionalChildrenIncByGrp ig2a join ig2a.pkey.requiredParentSubGroup sg2b join sg2b.optionalChildrenMembByGrp mb2 where sg2.requiredName = :parmPermName and mb2.pkey.requiredParentUser.requiredLoginId = :parmLoginId"
		+ " union select sg3.requiredName as requiredName from CFSecJpaSecSysGrp sg3 join sg3.optionalChildrenIncByGrp ig3 join ig3.pkey.requiredParentSubGroup sg3a join sg3a.optionalChildrenIncByGrp ig3a join ig3a.pkey.requiredParentSubGroup sg3b join sg3b.optionalChildrenIncByGrp ig3b join ig3b.pkey.requiredParentSubGroup sg3c join sg3c.optionalChildrenMembByGrp mb3 where sg3.requiredName = :parmPermName and mb3.pkey.requiredParentUser.requiredLoginId = :parmLoginId)")
	long countSysSecurityPermsByLoginId(@Param("parmPermName") String parmPermName, @Param("parmLoginId") String parmLoginId);

	/**
	 *	Count system-level security access for permission granted to a specific user by UserId.
	 *
	 *		@param parmPermName The name of the permission to be checked (all lowercase in the case of generated permission names; custom roles might be mixed-case)
	 *		@param parmUserId The UserId of the user being authorized.
	 *		@return The number of authorizations for the specified permission and user, with an 8-level deep union in play.
	 */
	@Query("select count(*) from ("
		+ "select sg0.requiredName as requiredName from CFSecJpaSecSysGrp sg0 join sg0.optionalChildrenMembByGrp mb0 join mb0.pkey.requiredParentUser pu0 where sg0.requiredName = :parmPermName and pu0.requiredSecUserId = :parmUserId"
		+ " union select sg1.requiredName as requiredName from CFSecJpaSecSysGrp sg1 join sg1.optionalChildrenIncByGrp ig1 join ig1.pkey.requiredParentSubGroup sg1a join sg1a.optionalChildrenMembByGrp mb1 join mb1.pkey.requiredParentUser pu1 where sg1.requiredName = :parmPermName and pu1.requiredSecUserId = :parmUserId"
		+ " union select sg2.requiredName as requiredName from CFSecJpaSecSysGrp sg2 join sg2.optionalChildrenIncByGrp ig2 join ig2.pkey.requiredParentSubGroup sg2a join sg2a.optionalChildrenIncByGrp ig2a join ig2a.pkey.requiredParentSubGroup sg2b join sg2b.optionalChildrenMembByGrp mb2 join mb2.pkey.requiredParentUser pu2 where sg2.requiredName = :parmPermName and pu2.requiredSecUserId = :parmUserId"
		+ " union select sg3.requiredName as requiredName from CFSecJpaSecSysGrp sg3 join sg3.optionalChildrenIncByGrp ig3 join ig3.pkey.requiredParentSubGroup sg3a join sg3a.optionalChildrenIncByGrp ig3a join ig3a.pkey.requiredParentSubGroup sg3b join sg3b.optionalChildrenIncByGrp ig3b join ig3b.pkey.requiredParentSubGroup sg3c join sg3c.optionalChildrenMembByGrp mb3 join mb3.pkey.requiredParentUser pu3 where sg3.requiredName = :parmPermName and pu3.requiredSecUserId = :parmUserId)")
	long countSysSecurityPermsByUserId(@Param("parmPermName") String parmPermName, @Param("parmUserId") CFLibDbKeyHash256 parmUserId);

}
