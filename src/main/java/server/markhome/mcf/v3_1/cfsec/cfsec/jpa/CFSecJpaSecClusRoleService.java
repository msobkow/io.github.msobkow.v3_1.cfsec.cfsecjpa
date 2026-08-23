// Description: Java 25 Spring JPA Service for SecClusRole

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
import server.markhome.mcf.v3_1.cflib.keyhash.*;
import server.markhome.mcf.v3_1.cflib.xml.CFLibXmlUtil;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.text.StringEscapeUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.orm.jpa.LocalContainerEntityManagerFactoryBean;
import server.markhome.mcf.v3_1.cfsec.cfsec.*;

/**
 *	Service for the CFSecSecClusRole entities defined in server.markhome.mcf.v3_1.cfsec.cfsec.jpa
 *	using the CFSecSecClusRoleRepository to access them.
 */
@Service("cfsec31JpaSecClusRoleService")
public class CFSecJpaSecClusRoleService {

	@Autowired
	@Qualifier("cfsec31EntityManagerFactory")
	private LocalContainerEntityManagerFactoryBean cfsec31EntityManagerFactory;

	@Autowired
	private CFSecJpaSecClusRoleRepository cfsec31SecClusRoleRepository;

	/**
	 *	Create an entity, generating any database keys required along the way.
	 *
	 *		@param	data	The entity to be instantiated; must be a specific instance of CFSecJpaSecClusRole, not a subclass.
	 *
	 *		@return The updated/created entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole create(CFSecJpaSecClusRole data) {
		final String S_ProcName = "create";
		if (data == null) {
			return( null );
		}
		ICFLibKeyHash256 originalRequiredSecClusRoleId = data.getRequiredSecClusRoleId();
		boolean generatedRequiredSecClusRoleId = false;
		if (data.getRequiredOwnerCluster() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Owner",
				"Owner",
				"data.requiredOwnerCluster",
				"data.requiredOwnerCluster",
				"Cluster",
				"Cluster",
				null);
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysGrp",
				"SecSysGrp",
				null);
		}
		if(data.getRequiredClusterId() == null || data.getRequiredClusterId().isNull()) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredClusterId");
		}
		if(data.getRequiredName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredName");
		}
		try {
			if(data.getPKey() != null && !data.getPKey().isNull() && cfsec31SecClusRoleRepository.existsById((ICFLibKeyHash256)data.getPKey())) {
				return( (CFSecJpaSecClusRole)(cfsec31SecClusRoleRepository.findById((ICFLibKeyHash256)(data.getPKey())).get()));
			}
			if (data.getRequiredRevision() <= 0) {
				data.setRequiredRevision(1);
			}
			if (data.getRequiredSecClusRoleId() == null || data.getRequiredSecClusRoleId().isNull()) {
				data.setRequiredSecClusRoleId(new CFLibDbKeyHash256(0));
				generatedRequiredSecClusRoleId = true;
			}
			LocalDateTime now = LocalDateTime.now();
			data.setCreatedAt(now);
			data.setUpdatedAt(now);
			return cfsec31SecClusRoleRepository.save(data);
		}
		catch(Exception ex) {
				if(generatedRequiredSecClusRoleId) {
					data.setRequiredSecClusRoleId(originalRequiredSecClusRoleId);
				}
			throw new CFLibDbException(getClass(),
				S_ProcName,
				ex);
		}
	}

	/**
	 *	Update an existing entity.
	 *
	 *		@param	data	The entity to be updated.
	 *
	 *		@return The updated entity.
	 */
	@Transactional(propagation = Propagation.REQUIRED,rollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole update(CFSecJpaSecClusRole data) {
		final String S_ProcName = "update";
		if (data == null) {
			return( null );
		}
		if (data.getPKey() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.getPKey()");
		}
		if (data.getRequiredOwnerCluster() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Owner",
				"Owner",
				"data.requiredOwnerCluster",
				"data.requiredOwnerCluster",
				"Cluster",
				"Cluster",
				null);
		}
		if (data.getRequiredContainerSysRole() == null) {
			throw new CFLibUnresolvedRelationException(getClass(),
				S_ProcName,
				"Container",
				"Container",
				"data.requiredContainerSysRole",
				"data.requiredContainerSysRole",
				"SecSysGrp",
				"SecSysGrp",
				null);
		}
		if(data.getRequiredClusterId() == null || data.getRequiredClusterId().isNull()) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredClusterId");
		}
		if(data.getRequiredName() == null) {
			throw new CFLibNullArgumentException(getClass(),
				S_ProcName,
				0,
				"data.requiredName");
		}
		// Ensure the entity exists and that the revision matches
		CFSecJpaSecClusRole existing = cfsec31SecClusRoleRepository.findById((ICFLibKeyHash256)(data.getPKey()))
			.orElseThrow(() -> new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey()));
		if (existing.getRequiredRevision() != data.getRequiredRevision()) {
			throw new CFLibCollisionDetectedException(getClass(), S_ProcName, data.getPKey());
		}
		// Apply superior data relationships of CFSecSecClusRole to existing object
		existing.setRequiredOwnerCluster(data.getRequiredOwnerCluster());
		existing.setRequiredContainerSysRole(data.getRequiredContainerSysRole());
		// Apply data columns of CFSecSecClusRole to existing object
		existing.setRequiredClusterId(data.getRequiredClusterId());
		existing.setRequiredName(data.getRequiredName());
		// Update the audit columns
		data.setUpdatedAt(LocalDateTime.now());
		// Save the changes we've made
		return cfsec31SecClusRoleRepository.save(existing);
	}

	/**
	 *	Argument-based find database instance for compatibility with the current MSS code factory code base.
	 *
	 *		@param requiredSecClusRoleId
	 *
	 *		@return The retrieved entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole find(@Param("secClusRoleId") ICFLibKeyHash256 requiredSecClusRoleId) {
		return( cfsec31SecClusRoleRepository.get(requiredSecClusRoleId));
	}

	/**
	 *	Retrieve all entities from the repository
	 *
	 *		@return The list of retrieved entities, which may be empty
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> findAll() {
		return( cfsec31SecClusRoleRepository.findAll() );
	}

	// CFSecSecClusRole specified index finders

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecClusRoleByClusterIdxKey as arguments.
	 *
	 *		@param requiredClusterId
	 *
	 *		@return List&lt;CFSecJpaSecClusRole&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> findByClusterIdx(@Param("clusterId") ICFLibKeyHash256 requiredClusterId) {
		return( cfsec31SecClusRoleRepository.findByClusterIdx(requiredClusterId));
	}

	/**
	 *	ICFSecSecClusRoleByClusterIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecClusRoleByClusterIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> findByClusterIdx(ICFSecSecClusRoleByClusterIdxKey key) {
		return( cfsec31SecClusRoleRepository.findByClusterIdx(key.getRequiredClusterId()));
	}

	/**
	 *	Find zero or more entities into a List using the columns of the ICFSecSecClusRoleByNameIdxKey as arguments.
	 *
	 *		@param requiredName
	 *
	 *		@return List&lt;CFSecJpaSecClusRole&gt; of the found entities, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> findByNameIdx(@Param("name") String requiredName) {
		return( cfsec31SecClusRoleRepository.findByNameIdx(requiredName));
	}

	/**
	 *	ICFSecSecClusRoleByNameIdxKey entity list finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecClusRoleByNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity list, which may be empty.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> findByNameIdx(ICFSecSecClusRoleByNameIdxKey key) {
		return( cfsec31SecClusRoleRepository.findByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Find an entity using the columns of the ICFSecSecClusRoleByUNameIdxKey as arguments.
	 *
	 *		@param requiredClusterId
	 *		@param requiredName
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole findByUNameIdx(@Param("clusterId") ICFLibKeyHash256 requiredClusterId,
		@Param("name") String requiredName) {
		return( cfsec31SecClusRoleRepository.findByUNameIdx(requiredClusterId,
			requiredName));
	}

	/**
	 *	ICFSecSecClusRoleByUNameIdxKey entity finder convenience method for object-based access.
	 *
	 *		@param key The ICFSecSecClusRoleByUNameIdxKey instance to use for the query arguments.
	 *
	 *		@return The found entity, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole findByUNameIdx(ICFSecSecClusRoleByUNameIdxKey key) {
		return( cfsec31SecClusRoleRepository.findByUNameIdx(key.getRequiredClusterId(), key.getRequiredName()));
	}

	// CFSecSecClusRole specified lock-by-index methods

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole lockByIdIdx(@Param("secClusRoleId") ICFLibKeyHash256 requiredSecClusRoleId) {
		return( cfsec31SecClusRoleRepository.lockByIdIdx(requiredSecClusRoleId));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> lockByClusterIdx(@Param("clusterId") ICFLibKeyHash256 requiredClusterId) {
		return( cfsec31SecClusRoleRepository.lockByClusterIdx(requiredClusterId));
	}

	/**
	 *	ICFSecSecClusRoleByClusterIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> lockByClusterIdx(ICFSecSecClusRoleByClusterIdxKey key) {
		return( cfsec31SecClusRoleRepository.lockByClusterIdx(key.getRequiredClusterId()));
	}

	/**
	 *	Argument-based lock database instance for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> lockByNameIdx(@Param("name") String requiredName) {
		return( cfsec31SecClusRoleRepository.lockByNameIdx(requiredName));
	}

	/**
	 *	ICFSecSecClusRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return A list of locked entities, refreshed from the data store, or an empty list if no such entities exist.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public List<CFSecJpaSecClusRole> lockByNameIdx(ICFSecSecClusRoleByNameIdxKey key) {
		return( cfsec31SecClusRoleRepository.lockByNameIdx(key.getRequiredName()));
	}

	/**
	 *	Argument-based lock database entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity locks, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 *		@param requiredName
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole lockByUNameIdx(@Param("clusterId") ICFLibKeyHash256 requiredClusterId,
		@Param("name") String requiredName) {
		return( cfsec31SecClusRoleRepository.lockByUNameIdx(requiredClusterId,
			requiredName));
	}

	/**
	 *	ICFSecSecClusRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The key of the entity to be locked.
	 *
	 *		@return The locked entity, refreshed from the data store, or null if no such entity exists.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public CFSecJpaSecClusRole lockByUNameIdx(ICFSecSecClusRoleByUNameIdxKey key) {
		return( cfsec31SecClusRoleRepository.lockByUNameIdx(key.getRequiredClusterId(), key.getRequiredName()));
	}

	// CFSecSecClusRole specified delete-by-index methods

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredSecClusRoleId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByIdIdx(@Param("secClusRoleId") ICFLibKeyHash256 requiredSecClusRoleId) {
		cfsec31SecClusRoleRepository.deleteByIdIdx(requiredSecClusRoleId);
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByClusterIdx(@Param("clusterId") ICFLibKeyHash256 requiredClusterId) {
		cfsec31SecClusRoleRepository.deleteByClusterIdx(requiredClusterId);
	}

	/**
	 *	ICFSecSecClusRoleByClusterIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecClusRoleByClusterIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByClusterIdx(ICFSecSecClusRoleByClusterIdxKey key) {
		cfsec31SecClusRoleRepository.deleteByClusterIdx(key.getRequiredClusterId());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(@Param("name") String requiredName) {
		cfsec31SecClusRoleRepository.deleteByNameIdx(requiredName);
	}

	/**
	 *	ICFSecSecClusRoleByNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecClusRoleByNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByNameIdx(ICFSecSecClusRoleByNameIdxKey key) {
		cfsec31SecClusRoleRepository.deleteByNameIdx(key.getRequiredName());
	}

	/**
	 *	Argument-based delete entity for compatibility with the current MSS code factory code base, uses @Transactional to acquire a JPA entity lock, which may or may not imply an actual database lock during the transaction.
	 *
	 *		@param requiredClusterId
	 *		@param requiredName
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUNameIdx(@Param("clusterId") ICFLibKeyHash256 requiredClusterId,
		@Param("name") String requiredName) {
		cfsec31SecClusRoleRepository.deleteByUNameIdx(requiredClusterId,
			requiredName);
	}

	/**
	 *	ICFSecSecClusRoleByUNameIdxKey based lock method for object-based access.
	 *
	 *		@param key The ICFSecSecClusRoleByUNameIdxKey of the entity to be locked.
	 */
	@Transactional(propagation = Propagation.REQUIRED, noRollbackFor = NoResultException.class, transactionManager = "cfsec31TransactionManager")
	public void deleteByUNameIdx(ICFSecSecClusRoleByUNameIdxKey key) {
		cfsec31SecClusRoleRepository.deleteByUNameIdx(key.getRequiredClusterId(), key.getRequiredName());
	}

}
