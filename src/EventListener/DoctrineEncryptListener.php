<?php

namespace SpecShaper\EncryptBundle\EventListener;

use Doctrine\ORM\EntityManagerInterface;
use Doctrine\ORM\Event\OnFlushEventArgs;
use Doctrine\ORM\Events;
use Doctrine\Persistence\Event\LifecycleEventArgs;
use ReflectionProperty;
use SpecShaper\EncryptBundle\Encryptors\EncryptorInterface;
use SpecShaper\EncryptBundle\Exception\EncryptException;
use Doctrine\Bundle\DoctrineBundle\Attribute\AsDoctrineListener;
use Doctrine\ORM\UnitOfWork;
use Doctrine\ORM\Mapping\ClassMetadata;

/**
 * Doctrine event listener which encrypts/decrypts entities.
 */
#[AsDoctrineListener(event: Events::postLoad, priority: 500)]
#[AsDoctrineListener(event: Events::postUpdate, priority: 500)]
#[AsDoctrineListener(event: Events::onFlush, priority: 500)]
class DoctrineEncryptListener implements DoctrineEncryptListenerInterface
{
    /**
     * Encryptor interface namespace.
     */
    public const ENCRYPTOR_INTERFACE_NS = EncryptorInterface::class;

    /**
     * An array of annotations which are to be encrypted.
     * The default and initial is the bundle Encrypted Class.
     */
    protected array $annotationArray;

    /**
     * Caches information on an entity's encrypted fields in an array keyed on
     * the entity's class name. The value will be a list of Reflected fields that are encrypted.
     */
    protected array $encryptedFieldCache = [];

    private array $rawValues = [];

    private bool $isDisabled;

    public function __construct(
        private readonly EncryptorInterface $encryptor,
        private readonly EntityManagerInterface $em,
        array $annotationArray,
        bool $isDisabled
    ) {
        $this->annotationArray = $annotationArray;
        $this->isDisabled = $isDisabled;
    }

    public function getEncryptor(): EncryptorInterface
    {
        return $this->encryptor;
    }

    /**
     * Set Is Disabled.
     *
     * Used to programmatically disable encryption on flush operations.
     * Decryption still occurs if values have the <ENC> suffix.
     */
    public function setIsDisabled(?bool $isDisabled = true): DoctrineEncryptListenerInterface
    {
        $this->isDisabled = $isDisabled;

        return $this;
    }

    /**
     * @throws EncryptException
     */
    public function onFlush(OnFlushEventArgs $args): void
    {
        if ($this->isDisabled) {
            return;
        }

        $unitOfWork = $this->em->getUnitOfWork();

        foreach ($unitOfWork->getScheduledEntityInsertions() as $entity) {
            $this->processFields($entity, true, true);
        }

        foreach ($unitOfWork->getScheduledEntityUpdates() as $entity) {
            $this->processFields($entity, true, false);
        }
    }

    /**
     * Listen a postLoad lifecycle event. Checking and decrypt entities
     * which have @Encrypted annotations.
     *
     * @throws EncryptException
     */
    public function postLoad(LifecycleEventArgs $args): void
    {
        $entity = $args->getObject();

        // Decrypt the entity fields.
        $this->processFields($entity, false, false);
    }

    /**
     * Decrypt a value.
     *
     * If the value is an object, or if it does not contain the suffix <ENC> then return the value itself back.
     * Otherwise, decrypt the value and return.
     */
    public function decryptValue(?string $value, ?string $columnName): ?string
    {
        // Else decrypt value and return.
        return $this->encryptor->decrypt($value, $columnName);
    }

    public function getEncryptionableProperties(array $allProperties): array
    {
        $encryptedFields = [];

        foreach ($allProperties as $refProperty) {
            if ($this->isEncryptedProperty($refProperty)) {
                $encryptedFields[] = $refProperty;
            }
        }

        return $encryptedFields;
    }

    protected function processFields(object $entity, bool $isEncryptOperation, bool $isInsert): bool
    {
        $unitOfWork = $this->em->getUnitOfWork();
        $oid = spl_object_id($entity);
        $meta = $this->em->getClassMetadata(get_class($entity));

        $processed = $this->processEntityFields($entity, $isEncryptOperation, $isInsert, $unitOfWork, $meta);

        // Process embeddable
        foreach ($meta->embeddedClasses as $embeddedField => $embeddedClass) {
            $embeddedEntity = $meta->getFieldValue($entity, $embeddedField);
            if ($embeddedEntity) {
                $embeddedMeta = $this->em->getClassMetadata($embeddedClass['class']);
                $processed |= $this->processEntityFields($embeddedEntity, $isEncryptOperation, $isInsert, $unitOfWork, $embeddedMeta, $entity, $embeddedField);
            }
        }

        if ($isInsert && isset($this->rawValues[$oid])) {
            // Restore the decrypted values after the change set update
            foreach ($this->rawValues[$oid] as $prop => $rawValue) {
                $refProperty = $meta->getReflectionProperty($prop);
                $refProperty->setValue($entity, $rawValue);
            }

            unset($this->rawValues[$oid]);
        }

        return $processed;
    }

    protected function processEntityFields(object $entity, bool $isEncryptOperation, bool $isInsert, UnitOfWork $unitOfWork, ClassMetadata $meta, ?object $parentEntity = null, ?string $embeddedField = null): bool
    {
        // Get the encrypted properties in the entity.
        $properties = $this->getEncryptedFields($entity);

        // If no encrypted properties, return false.
        if (empty($properties)) {
            return false;
        }

        $oid = spl_object_id($entity);

        foreach ($properties as $refProperty) {
            $field = $refProperty->getName();

            // Get the value in the entity.
            $value = $refProperty->getValue($entity);

            // Skip any null values.
            if (null === $value) {
                continue;
            }

            if (is_object($value)) {
                continue;
            }

            // Encryption is fired by onFlush event, else it is an onLoad event.
            if ($isEncryptOperation) {
                $changeSet = $parentEntity ? $unitOfWork->getEntityChangeSet($parentEntity) : $unitOfWork->getEntityChangeSet($entity);

                // Encrypt value only if change has been detected by Doctrine (comparing unencrypted values, see postLoad flow)
                if (isset($changeSet[$embeddedField ? $embeddedField : $field])) {
                    $encryptedValue = $this->encryptor->encrypt($value, $field);
                    $refProperty->setValue($entity, $encryptedValue);

                    if ($parentEntity) {
                        $unitOfWork->recomputeSingleEntityChangeSet($meta, $parentEntity);
                    } else {
                        $unitOfWork->recomputeSingleEntityChangeSet($meta, $entity);
                    }

                    // Will be restored during postUpdate cycle for updates, or below for inserts
                    $this->rawValues[$oid][$field] = $value;
                }
            } else {
                // Decryption is fired by onLoad and postFlush events.
                $decryptedValue = $this->decryptValue($value, $field);
                $refProperty->setValue($entity, $decryptedValue);

                // Tell Doctrine the original value was the decrypted one.
                if ($parentEntity) {
                    $unitOfWork->setOriginalEntityProperty(spl_object_id($parentEntity), $embeddedField, $parentEntity->$embeddedField);
                } else {
                    $unitOfWork->setOriginalEntityProperty($oid, $field, $decryptedValue);
                }
            }
        }

        return true;
    }

    public function postUpdate(LifecycleEventArgs $args): void
    {
        $entity = $args->getObject();
        $oid = spl_object_id($entity);

        if (isset($this->rawValues[$oid])) {
            $className = get_class($entity);
            $meta = $this->em->getClassMetadata($className);
            foreach ($this->rawValues[$oid] as $prop => $rawValue) {
                $refProperty = $meta->getReflectionProperty($prop);
                $refProperty->setValue($entity, $rawValue);
            }

            unset($this->rawValues[$oid]);
        }
    }

    /**
     * @return array<string, ReflectionProperty>
     */
    protected function getEncryptedFields(object $entity): array
    {
        $reflectionClass = $this->getOriginalEntityReflection($entity);

        $className = $reflectionClass->getName();

        if (isset($this->encryptedFieldCache[$className])) {
            return $this->encryptedFieldCache[$className];
        }

        $properties = $reflectionClass->getProperties();

        $encryptedFields = [];

        foreach ($properties as $key => $refProperty) {
            if ($this->isEncryptedProperty($refProperty)) {
                $encryptedFields[$key] = $refProperty;
            }
        }

        // Handle embedded properties
        foreach ($this->em->getClassMetadata($className)->embeddedClasses as $embeddedField => $embeddedClass) {
            $embeddedReflection = new \ReflectionClass($embeddedClass['class']);
            $embeddedProperties = $embeddedReflection->getProperties();

            foreach ($embeddedProperties as $key => $refProperty) {
                if ($this->isEncryptedProperty($refProperty)) {
                    $encryptedFields[$embeddedField . '.' . $key] = $refProperty;
                }
            }
        }

        $this->encryptedFieldCache[$className] = $encryptedFields;

        return $encryptedFields;
    }

    private function isEncryptedProperty(ReflectionProperty $refProperty)
    {
        // If PHP8, and has attributes.
        if(method_exists($refProperty, 'getAttributes')) {
            foreach ($refProperty->getAttributes() as $refAttribute) {
                if (in_array($refAttribute->getName(), $this->annotationArray)) {
                    return true;
                }
            }
        }

        return false;
    }

    protected function getOriginalEntityReflection($entity): \ReflectionClass
    {
        $realClassName = $this->em->getClassMetadata(get_class($entity))->getName();
        return new \ReflectionClass($realClassName);
    }
}